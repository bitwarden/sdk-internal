use std::{marker::PhantomData, num::TryFromIntError, str::FromStr};

use argon2::Params;
use base64::{engine::general_purpose::STANDARD, Engine};
use ciborium::{value::Integer, Value};
use coset::{
    iana::CoapContentFormat, CborSerializable, ContentType, CoseError, Header, HeaderBuilder,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    cose::{
        extract_bytes, extract_integer, CoseExtractError, ALG_ARGON2ID13, ARGON2_ITERATIONS,
        ARGON2_MEMORY, ARGON2_PARALLELISM, ARGON2_SALT, CONTENT_TYPE_BITWARDEN_LEGACY_KEY,
    },
    xchacha20, BitwardenLegacyKeyBytes, ContentFormat, CoseKeyBytes, EncodedSymmetricKey,
    FromStrVisitor, KeyIds, KeyStoreContext, SymmetricCryptoKey,
};

/// A password-protected key envelope can seal a symmetric key, and protect it with a password. It
/// does so by using a Key Derivation Function (KDF), to increase the difficulty of brute-forcing
/// the password.
///
/// The KDF parameters such as iterations and salt are stored in the key-envelope and do not have to
/// be provided.
///
/// Internally, Argon2 as the KDF, and XChaCha20-Poly1305 are used to encrypt the message.
pub struct PasswordProtectedKeyEnvelope<Ids: KeyIds> {
    _phantom: PhantomData<Ids>,
    cose_encrypt: coset::CoseEncrypt,
}

impl<Ids: KeyIds> PasswordProtectedKeyEnvelope<Ids> {
    /// Seals a symmetric key with a password, using the current default KDF parameters and a random
    /// salt.
    ///
    /// This should never fail, except for memory allocation error, when running the KDF.
    pub fn seal(
        key_to_seal: Ids::Symmetric,
        password: &str,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<Self, PasswordProtectedKeyEnvelopeError> {
        #[allow(deprecated)]
        let key_ref = ctx
            .dangerous_get_symmetric_key(key_to_seal)
            .map_err(|_| PasswordProtectedKeyEnvelopeError::KeyMissingError)?;
        Self::seal_ref(key_ref, password)
    }

    /// Seals a key reference with a password. This function is not public since callers are
    /// expected to only work with key store references.
    fn seal_ref(
        key_to_seal: &SymmetricCryptoKey,
        password: &str,
    ) -> Result<Self, PasswordProtectedKeyEnvelopeError> {
        Self::seal_ref_with_settings(
            key_to_seal,
            password,
            &Argon2RawSettings::default_for_platform(),
        )
    }

    /// Seals a key reference with a password and custom provided settings. This function is not
    /// public since callers are expected to only work with key store references, and to not
    /// control the KDF difficulty where possible.
    fn seal_ref_with_settings(
        key_to_seal: &SymmetricCryptoKey,
        password: &str,
        kdf_settings: &Argon2RawSettings,
    ) -> Result<Self, PasswordProtectedKeyEnvelopeError> {
        // Cose does not yet have a standardized way to protect a key using a password.
        // This implements content encryption using direct encryption with a KDF derived key,
        // similar to "Direct Key with KDF" mentioned in the COSE spec. The KDF settings are
        // placed in a single recipient struct.

        // The envelope key is directly derived from the KDF and used as the key to encrypt the key
        // that should be sealed.
        let envelope_key = derive_key(kdf_settings, password)
            .map_err(|_| PasswordProtectedKeyEnvelopeError::KdfError)?;

        let (content_format, key_to_seal_bytes) = match key_to_seal.to_encoded_raw() {
            EncodedSymmetricKey::BitwardenLegacyKey(key_bytes) => {
                (ContentFormat::BitwardenLegacyKey, key_bytes.to_vec())
            }
            EncodedSymmetricKey::CoseKey(key_bytes) => (ContentFormat::CoseKey, key_bytes.to_vec()),
        };

        let mut nonce = [0u8; crate::xchacha20::NONCE_SIZE];

        // The message is constructed by placing the KDF settings in a recipient struct's
        // unprotected headers. They do not need to live in the protected header, since to
        // authenticate the protected header, the settings must be correct.
        let mut cose_encrypt = coset::CoseEncryptBuilder::new()
            .add_recipient({
                let mut recipient = coset::CoseRecipientBuilder::new()
                    .unprotected(kdf_settings.into())
                    .build();
                recipient.protected.header.alg = Some(coset::Algorithm::PrivateUse(ALG_ARGON2ID13));
                recipient
            })
            .protected(HeaderBuilder::from(content_format).build())
            .create_ciphertext(&key_to_seal_bytes, &[], |data, aad| {
                let ciphertext = xchacha20::encrypt_xchacha20_poly1305(&envelope_key, data, aad);
                nonce.copy_from_slice(&ciphertext.nonce());
                ciphertext.encrypted_bytes().to_vec()
            })
            .build();
        cose_encrypt.unprotected.iv = nonce.into();

        Ok(PasswordProtectedKeyEnvelope {
            _phantom: PhantomData,
            cose_encrypt,
        })
    }

    /// Unseals a symmetric key from the password-protected envelope, and stores it in the key store
    /// context.
    pub fn unseal(
        &self,
        target_keyslot: Ids::Symmetric,
        password: &str,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Symmetric, PasswordProtectedKeyEnvelopeError> {
        let key = self.unseal_ref(password)?;
        #[allow(deprecated)]
        ctx.set_symmetric_key(target_keyslot, key)
            .map_err(|_| PasswordProtectedKeyEnvelopeError::KeyStoreError)?;
        Ok(target_keyslot)
    }

    fn unseal_ref(
        &self,
        password: &str,
    ) -> Result<SymmetricCryptoKey, PasswordProtectedKeyEnvelopeError> {
        // There must be exactly one recipient in the COSE Encrypt object, which contains the KDF
        // parameters.
        if self.cose_encrypt.recipients.len() != 1 {
            return Err(PasswordProtectedKeyEnvelopeError::ParsingError(
                "Invalid number of recipients".to_string(),
            ));
        }

        let recipient = self.cose_encrypt.recipients.first().ok_or(
            PasswordProtectedKeyEnvelopeError::ParsingError("Missing recipient".to_string()),
        )?;
        if recipient.protected.header.alg != Some(coset::Algorithm::PrivateUse(ALG_ARGON2ID13)) {
            return Err(PasswordProtectedKeyEnvelopeError::ParsingError(
                "Unknown or unsupported KDF algorithm".to_string(),
            ));
        }

        let kdf_settings: Argon2RawSettings =
            (&recipient.unprotected).try_into().map_err(|_| {
                PasswordProtectedKeyEnvelopeError::ParsingError(
                    "Invalid or missing KDF parameters".to_string(),
                )
            })?;
        let envelope_key = derive_key(&kdf_settings, password)
            .map_err(|_| PasswordProtectedKeyEnvelopeError::KdfError)?;
        let nonce: [u8; 24] = self
            .cose_encrypt
            .unprotected
            .iv
            .clone()
            .try_into()
            .map_err(|_| {
                PasswordProtectedKeyEnvelopeError::ParsingError("Invalid IV".to_string())
            })?;

        let key_bytes = self
            .cose_encrypt
            .decrypt(&[], |data, aad| {
                xchacha20::decrypt_xchacha20_poly1305(&nonce, &envelope_key, data, aad)
            })
            // If decryption fails, the envelope-key is incorrect and thus the password is incorrect
            // since the KDF parameters & salt are guaranteed to be correct
            .map_err(|_| PasswordProtectedKeyEnvelopeError::WrongPassword)?;

        SymmetricCryptoKey::try_from(
            match self.cose_encrypt.protected.header.content_type.as_ref() {
                Some(ContentType::Text(format)) if format == CONTENT_TYPE_BITWARDEN_LEGACY_KEY => {
                    EncodedSymmetricKey::BitwardenLegacyKey(BitwardenLegacyKeyBytes::from(
                        key_bytes,
                    ))
                }
                Some(ContentType::Assigned(CoapContentFormat::CoseKey)) => {
                    EncodedSymmetricKey::CoseKey(CoseKeyBytes::from(key_bytes))
                }
                _ => {
                    return Err(PasswordProtectedKeyEnvelopeError::ParsingError(
                        "Unknown or unsupported content format".to_string(),
                    ));
                }
            },
        )
        .map_err(|_| {
            PasswordProtectedKeyEnvelopeError::ParsingError("Failed to decode key".to_string())
        })
    }

    /// Re-seals the key with new KDF parameters (updated settings, salt), and a new password
    pub fn reseal(
        &self,
        password: &str,
        new_password: &str,
    ) -> Result<Self, PasswordProtectedKeyEnvelopeError> {
        let unsealed = self.unseal_ref(password)?;
        Self::seal_ref(&unsealed, new_password)
    }
}

impl<Ids: KeyIds> From<&PasswordProtectedKeyEnvelope<Ids>> for Vec<u8> {
    fn from(val: &PasswordProtectedKeyEnvelope<Ids>) -> Self {
        val.cose_encrypt
            .clone()
            .to_vec()
            .expect("Serialization to cose should not fail")
    }
}

impl<Ids: KeyIds> TryFrom<&Vec<u8>> for PasswordProtectedKeyEnvelope<Ids> {
    type Error = CoseError;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        let cose_encrypt = coset::CoseEncrypt::from_slice(value)?;
        Ok(PasswordProtectedKeyEnvelope {
            _phantom: PhantomData,
            cose_encrypt,
        })
    }
}

impl<Ids: KeyIds> std::fmt::Debug for PasswordProtectedKeyEnvelope<Ids> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordProtectedKeyEnvelope")
            .field("cose_encrypt", &self.cose_encrypt)
            .finish()
    }
}

impl<Ids: KeyIds> FromStr for PasswordProtectedKeyEnvelope<Ids> {
    type Err = PasswordProtectedKeyEnvelopeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = STANDARD.decode(s).map_err(|_| {
            PasswordProtectedKeyEnvelopeError::ParsingError(
                "Invalid PasswordProtectedKeyEnvelope Base64 encoding".to_string(),
            )
        })?;
        Self::try_from(&data).map_err(|_| {
            PasswordProtectedKeyEnvelopeError::ParsingError(
                "Failed to parse PasswordProtectedKeyEnvelope".to_string(),
            )
        })
    }
}

impl<Ids: KeyIds> From<PasswordProtectedKeyEnvelope<Ids>> for String {
    fn from(val: PasswordProtectedKeyEnvelope<Ids>) -> Self {
        let serialized: Vec<u8> = (&val).into();
        STANDARD.encode(serialized)
    }
}

impl<'de, Ids: KeyIds> Deserialize<'de> for PasswordProtectedKeyEnvelope<Ids> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new())
    }
}

impl<Ids: KeyIds> Serialize for PasswordProtectedKeyEnvelope<Ids> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let serialized: Vec<u8> = self.into();
        serializer.serialize_str(&STANDARD.encode(serialized))
    }
}

/// Raw argon2 settings differ from the KDF struct defined for existing master-password unlock.
/// The memory is represented in kibibytes (KiB) instead of mebibytes (MiB), and the salt is a fixed
/// size of 32 bytes, and randomly generated, instead of being derived from the email.
struct Argon2RawSettings {
    iterations: u32,
    /// Memory in KiB
    memory: u32,
    parallelism: u32,
    salt: [u8; 32],
}

impl Argon2RawSettings {
    /// Creates default Argon2 settings based on the platform. This currently is a static preset
    /// based on the target os
    fn default_for_platform() -> Self {
        // iOS has memory limitations in the auto-fill context. So, the memory is halved
        // but the iterations are doubled
        if cfg!(target_os = "ios") {
            // The SECOND RECOMMENDED option from: https://datatracker.ietf.org/doc/rfc9106/, with halved memory and doubled iteration count
            Self {
                iterations: 6,
                memory: 32 * 1024, // 32 MiB
                parallelism: 4,
                salt: make_salt(),
            }
        } else {
            // The SECOND RECOMMENDED option from: https://datatracker.ietf.org/doc/rfc9106/
            // The FIRST RECOMMENDED option currently still has too much memory consumption for most
            // clients except desktop.
            Self {
                iterations: 3,
                memory: 64 * 1024, // 64 MiB
                parallelism: 4,
                salt: make_salt(),
            }
        }
    }
}

impl From<&Argon2RawSettings> for Header {
    fn from(settings: &Argon2RawSettings) -> Header {
        let builder = HeaderBuilder::new()
            .value(ARGON2_ITERATIONS, Integer::from(settings.iterations).into())
            .value(ARGON2_MEMORY, Integer::from(settings.memory).into())
            .value(
                ARGON2_PARALLELISM,
                Integer::from(settings.parallelism).into(),
            )
            .value(ARGON2_SALT, Value::from(settings.salt.to_vec()));

        let mut header = builder.build();
        header.alg = Some(coset::Algorithm::PrivateUse(ALG_ARGON2ID13));
        header
    }
}

impl TryInto<Params> for &Argon2RawSettings {
    type Error = PasswordProtectedKeyEnvelopeError;

    fn try_into(self) -> Result<Params, PasswordProtectedKeyEnvelopeError> {
        Params::new(self.memory, self.iterations, self.parallelism, Some(32))
            .map_err(|_| PasswordProtectedKeyEnvelopeError::KdfError)
    }
}

impl TryInto<Argon2RawSettings> for &Header {
    type Error = PasswordProtectedKeyEnvelopeError;

    fn try_into(self) -> Result<Argon2RawSettings, PasswordProtectedKeyEnvelopeError> {
        Ok(Argon2RawSettings {
            iterations: extract_integer(self, ARGON2_ITERATIONS, "iterations")?.try_into()?,
            memory: extract_integer(self, ARGON2_MEMORY, "memory")?.try_into()?,
            parallelism: extract_integer(self, ARGON2_PARALLELISM, "parallelism")?.try_into()?,
            salt: extract_bytes(self, ARGON2_SALT, "salt")?
                .try_into()
                .map_err(|_| {
                    PasswordProtectedKeyEnvelopeError::ParsingError(
                        "Invalid Argon2 salt".to_string(),
                    )
                })?,
        })
    }
}

fn make_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

fn derive_key(
    argon2_settings: &Argon2RawSettings,
    password: &str,
) -> Result<[u8; 32], PasswordProtectedKeyEnvelopeError> {
    use argon2::*;

    let mut hash = [0u8; 32];
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        argon2_settings.try_into()?,
    )
    .hash_password_into(password.as_bytes(), &argon2_settings.salt, &mut hash)
    .map_err(|_| PasswordProtectedKeyEnvelopeError::KdfError)?;

    Ok(hash)
}

/// Errors that can occur when sealing or unsealing a key with the `PasswordProtectedKeyEnvelope`.
#[derive(Debug, Error)]
pub enum PasswordProtectedKeyEnvelopeError {
    /// The password provided is incorrect or the envelope was tampered with
    #[error("Wrong password")]
    WrongPassword,
    /// The envelope could not be parsed correctly, or the KDF parameters are invalid
    #[error("Parsing error {0}")]
    ParsingError(String),
    /// The KDF failed to derive a key, possibly due to invalid parameters or memory allocation
    /// issues
    #[error("Kdf error")]
    KdfError,
    /// There is no key for the provided key id in the key store
    #[error("Key missing error")]
    KeyMissingError,
    /// The key store could not be written to, for example due to being read-only
    #[error("Could not write to key store")]
    KeyStoreError,
}

impl From<CoseExtractError> for PasswordProtectedKeyEnvelopeError {
    fn from(err: CoseExtractError) -> Self {
        let CoseExtractError::MissingValue(label) = err;
        PasswordProtectedKeyEnvelopeError::ParsingError(format!("Missing value for {}", label))
    }
}

impl From<TryFromIntError> for PasswordProtectedKeyEnvelopeError {
    fn from(err: TryFromIntError) -> Self {
        PasswordProtectedKeyEnvelopeError::ParsingError(format!("Invalid integer: {}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        traits::tests::{TestIds, TestSymmKey},
        KeyStore,
    };

    const TESTVECTOR_COSEKEY_ENVELOPE: &[u8] = &[
        132, 68, 161, 3, 24, 101, 161, 5, 88, 24, 173, 142, 229, 217, 156, 211, 58, 187, 48, 229,
        94, 63, 201, 106, 223, 123, 129, 149, 111, 108, 216, 234, 114, 242, 88, 84, 7, 21, 43, 61,
        136, 100, 166, 73, 66, 77, 244, 30, 110, 208, 228, 170, 69, 37, 144, 43, 124, 28, 63, 202,
        233, 27, 49, 217, 144, 182, 88, 129, 128, 233, 209, 11, 89, 15, 138, 146, 163, 147, 198,
        182, 151, 227, 147, 183, 28, 124, 183, 83, 47, 84, 223, 129, 131, 217, 203, 128, 180, 109,
        45, 247, 181, 136, 8, 23, 30, 113, 229, 90, 121, 182, 162, 209, 249, 55, 17, 189, 200, 69,
        4, 254, 129, 131, 71, 161, 1, 58, 0, 1, 21, 87, 165, 1, 58, 0, 1, 21, 87, 58, 0, 1, 21, 89,
        3, 58, 0, 1, 21, 90, 26, 0, 1, 0, 0, 58, 0, 1, 21, 91, 4, 58, 0, 1, 21, 88, 88, 32, 168,
        162, 100, 184, 10, 1, 169, 18, 176, 1, 201, 181, 212, 40, 154, 8, 81, 194, 251, 57, 226,
        182, 247, 242, 237, 175, 189, 254, 89, 218, 226, 158, 246,
    ];
    const TEST_UNSEALED_COSEKEY_ENCODED: &[u8] = &[
        165, 1, 4, 2, 80, 80, 63, 72, 147, 13, 151, 69, 121, 184, 220, 160, 176, 227, 247, 83, 112,
        3, 58, 0, 1, 17, 111, 4, 132, 3, 4, 5, 6, 32, 88, 32, 95, 169, 162, 129, 95, 51, 121, 95,
        226, 3, 25, 67, 120, 143, 6, 169, 235, 157, 217, 6, 224, 25, 126, 237, 82, 169, 60, 245,
        122, 3, 35, 250, 1,
    ];

    const TESTVECTOR_LEGACYKEY_ENVELOPE: &[u8] = &[
        132, 88, 38, 161, 3, 120, 34, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 120,
        46, 98, 105, 116, 119, 97, 114, 100, 101, 110, 46, 108, 101, 103, 97, 99, 121, 45, 107,
        101, 121, 161, 5, 88, 24, 64, 18, 232, 33, 184, 69, 105, 229, 203, 52, 40, 19, 228, 121,
        232, 82, 6, 253, 145, 215, 99, 4, 88, 149, 88, 80, 16, 4, 72, 82, 162, 71, 130, 214, 222,
        19, 97, 28, 23, 82, 10, 222, 115, 60, 208, 71, 178, 128, 132, 129, 173, 19, 148, 119, 91,
        72, 155, 49, 172, 139, 4, 71, 209, 90, 110, 239, 180, 150, 23, 213, 134, 34, 52, 59, 27,
        40, 86, 86, 225, 49, 63, 39, 219, 197, 163, 90, 146, 204, 205, 93, 166, 199, 73, 72, 118,
        36, 11, 35, 124, 96, 209, 157, 75, 69, 24, 90, 129, 131, 71, 161, 1, 58, 0, 1, 21, 87, 165,
        1, 58, 0, 1, 21, 87, 58, 0, 1, 21, 89, 3, 58, 0, 1, 21, 90, 26, 0, 1, 0, 0, 58, 0, 1, 21,
        91, 4, 58, 0, 1, 21, 88, 88, 32, 89, 248, 223, 6, 137, 20, 160, 157, 139, 147, 235, 241,
        162, 143, 82, 84, 221, 133, 13, 15, 207, 253, 7, 17, 96, 75, 80, 31, 241, 241, 191, 97,
        246,
    ];
    const TEST_UNSEALED_LEGACYKEY_ENCODED: &[u8] = &[
        231, 34, 128, 103, 132, 210, 72, 65, 163, 123, 158, 12, 87, 153, 92, 230, 220, 186, 114,
        185, 42, 83, 62, 49, 190, 95, 188, 14, 111, 233, 136, 210, 202, 127, 163, 160, 70, 45, 135,
        210, 236, 237, 180, 212, 215, 151, 220, 250, 32, 184, 100, 154, 226, 23, 204, 106, 64, 85,
        205, 152, 118, 138, 199, 129,
    ];

    const TESTVECTOR_PASSWORD: &str = "test_password";

    #[test]
    fn test_testvector_cosekey() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx: KeyStoreContext<'_, TestIds> = key_store.context_mut();
        let envelope =
            PasswordProtectedKeyEnvelope::try_from(&TESTVECTOR_COSEKEY_ENVELOPE.to_vec())
                .expect("Key envelope should be valid");
        envelope
            .unseal(TestSymmKey::A(0), TESTVECTOR_PASSWORD, &mut ctx)
            .expect("Unsealing should succeed");
        #[allow(deprecated)]
        let unsealed_key = ctx
            .dangerous_get_symmetric_key(TestSymmKey::A(0))
            .expect("Key should exist in the key store");
        assert_eq!(
            unsealed_key.to_encoded().to_vec(),
            TEST_UNSEALED_COSEKEY_ENCODED
        );
    }

    #[test]
    fn test_testvector_legacykey() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx: KeyStoreContext<'_, TestIds> = key_store.context_mut();
        let envelope =
            PasswordProtectedKeyEnvelope::try_from(&TESTVECTOR_LEGACYKEY_ENVELOPE.to_vec())
                .expect("Key envelope should be valid");
        envelope
            .unseal(TestSymmKey::A(0), TESTVECTOR_PASSWORD, &mut ctx)
            .expect("Unsealing should succeed");
        #[allow(deprecated)]
        let unsealed_key = ctx
            .dangerous_get_symmetric_key(TestSymmKey::A(0))
            .expect("Key should exist in the key store");
        assert_eq!(
            unsealed_key.to_encoded().to_vec(),
            TEST_UNSEALED_LEGACYKEY_ENCODED
        );
    }

    #[test]
    fn test_make_envelope() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx: KeyStoreContext<'_, TestIds> = key_store.context_mut();
        let test_key = ctx.make_cose_symmetric_key(TestSymmKey::A(0)).unwrap();

        let password = "test_password";

        // Seal the key with a password
        let envelope = PasswordProtectedKeyEnvelope::seal(test_key, password, &ctx).unwrap();
        let serialized: Vec<u8> = (&envelope).into();

        // Unseal the key from the envelope
        let deserialized: PasswordProtectedKeyEnvelope<TestIds> =
            PasswordProtectedKeyEnvelope::try_from(&serialized).unwrap();
        deserialized
            .unseal(TestSymmKey::A(1), password, &mut ctx)
            .unwrap();

        // Verify that the unsealed key matches the original key
        #[allow(deprecated)]
        let unsealed_key = ctx
            .dangerous_get_symmetric_key(TestSymmKey::A(1))
            .expect("Key should exist in the key store");

        #[allow(deprecated)]
        let key_before_sealing = ctx
            .dangerous_get_symmetric_key(test_key)
            .expect("Key should exist in the key store");

        assert_eq!(unsealed_key, key_before_sealing);
    }

    #[test]
    fn test_make_envelope_legacy_key() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx: KeyStoreContext<'_, TestIds> = key_store.context_mut();
        let test_key = ctx.generate_symmetric_key(TestSymmKey::A(0)).unwrap();

        let password = "test_password";

        // Seal the key with a password
        let envelope = PasswordProtectedKeyEnvelope::seal(test_key, password, &ctx).unwrap();
        let serialized: Vec<u8> = (&envelope).into();

        // Unseal the key from the envelope
        let deserialized: PasswordProtectedKeyEnvelope<TestIds> =
            PasswordProtectedKeyEnvelope::try_from(&serialized).unwrap();
        deserialized
            .unseal(TestSymmKey::A(1), password, &mut ctx)
            .unwrap();

        // Verify that the unsealed key matches the original key
        #[allow(deprecated)]
        let unsealed_key = ctx
            .dangerous_get_symmetric_key(TestSymmKey::A(1))
            .expect("Key should exist in the key store");

        #[allow(deprecated)]
        let key_before_sealing = ctx
            .dangerous_get_symmetric_key(test_key)
            .expect("Key should exist in the key store");

        assert_eq!(unsealed_key, key_before_sealing);
    }

    #[test]
    fn test_reseal_envelope() {
        let key = SymmetricCryptoKey::make_xchacha20_poly1305_key();
        let password = "test_password";
        let new_password = "new_test_password";

        // Seal the key with a password
        let envelope: PasswordProtectedKeyEnvelope<TestIds> =
            PasswordProtectedKeyEnvelope::seal_ref(&key, password).expect("Sealing should work");

        // Reseal
        let envelope = envelope
            .reseal(password, new_password)
            .expect("Resealing should work");
        let unsealed = envelope
            .unseal_ref(new_password)
            .expect("Unsealing should work");

        // Verify that the unsealed key matches the original key
        assert_eq!(unsealed, key);
    }

    #[test]
    fn test_wrong_password() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx: KeyStoreContext<'_, TestIds> = key_store.context_mut();
        let test_key = ctx.make_cose_symmetric_key(TestSymmKey::A(0)).unwrap();

        let password = "test_password";
        let wrong_password = "wrong_password";

        // Seal the key with a password
        let envelope = PasswordProtectedKeyEnvelope::seal(test_key, password, &ctx).unwrap();

        // Attempt to unseal with the wrong password
        let deserialized: PasswordProtectedKeyEnvelope<TestIds> =
            PasswordProtectedKeyEnvelope::try_from(&(&envelope).into()).unwrap();
        assert!(matches!(
            deserialized.unseal(TestSymmKey::A(1), wrong_password, &mut ctx),
            Err(PasswordProtectedKeyEnvelopeError::WrongPassword)
        ));
    }
}

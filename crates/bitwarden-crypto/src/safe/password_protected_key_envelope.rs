//! Password protected key envelope is a cryptographic building block that allows sealing a
//! symmetric key with a low entropy secret (password, PIN, etc.).
//!
//! It is implemented by using a KDF (Argon2ID) combined with secret key encryption
//! (XChaCha20-Poly1305). The KDF prevents brute-force by requiring work to be done to derive the
//! key from the password.
//!
//! For the consumer, the output is an opaque blob that can be later unsealed with the same
//! password. The KDF parameters and salt are contained in the envelope, and don't need to be
//! provided for unsealing.
//!
//! Internally, the envelope is a CoseEncrypt object. The KDF parameters / salt are placed in the
//! single recipient's unprotected headers. The output from the KDF - "envelope key", is used to
//! wrap the symmetric key, that is sealed by the envelope.

use std::{marker::PhantomData, num::TryFromIntError, str::FromStr};

use argon2::Params;
use bitwarden_encoding::{B64, FromStrVisitor};
use ciborium::{Value, value::Integer};
use coset::{CborSerializable, CoseError, Header, HeaderBuilder};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    BitwardenLegacyKeyBytes, ContentFormat, CoseKeyBytes, EncodedSymmetricKey, KeyIds,
    KeyStoreContext, SymmetricCryptoKey,
    cose::{
        ALG_ARGON2ID13, ARGON2_ITERATIONS, ARGON2_MEMORY, ARGON2_PARALLELISM, ARGON2_SALT,
        CoseExtractError, extract_bytes, extract_integer,
    },
    xchacha20,
};

/// 16 is the RECOMMENDED salt size for all applications:
/// <https://datatracker.ietf.org/doc/rfc9106/>
const ENVELOPE_ARGON2_SALT_SIZE: usize = 16;
/// 32 is chosen to match the size of an XChaCha20-Poly1305 key
const ENVELOPE_ARGON2_OUTPUT_KEY_SIZE: usize = 32;

/// A password-protected key envelope can seal a symmetric key, and protect it with a password. It
/// does so by using a Key Derivation Function (KDF), to increase the difficulty of brute-forcing
/// the password.
///
/// The KDF parameters such as iterations and salt are stored in the envelope and do not have to
/// be provided.
///
/// Internally, Argon2 is used as the KDF and XChaCha20-Poly1305 is used to encrypt the key.
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
            .map_err(|_| PasswordProtectedKeyEnvelopeError::KeyMissing)?;
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
            &Argon2RawSettings::local_kdf_settings(),
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
            .map_err(|_| PasswordProtectedKeyEnvelopeError::Kdf)?;

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
            .map_err(|_| PasswordProtectedKeyEnvelopeError::KeyStore)?;
        Ok(target_keyslot)
    }

    fn unseal_ref(
        &self,
        password: &str,
    ) -> Result<SymmetricCryptoKey, PasswordProtectedKeyEnvelopeError> {
        // There must be exactly one recipient in the COSE Encrypt object, which contains the KDF
        // parameters.
        let recipient = self
            .cose_encrypt
            .recipients
            .first()
            .filter(|_| self.cose_encrypt.recipients.len() == 1)
            .ok_or_else(|| {
                PasswordProtectedKeyEnvelopeError::Parsing(
                    "Invalid number of recipients".to_string(),
                )
            })?;

        if recipient.protected.header.alg != Some(coset::Algorithm::PrivateUse(ALG_ARGON2ID13)) {
            return Err(PasswordProtectedKeyEnvelopeError::Parsing(
                "Unknown or unsupported KDF algorithm".to_string(),
            ));
        }

        let kdf_settings: Argon2RawSettings =
            (&recipient.unprotected).try_into().map_err(|_| {
                PasswordProtectedKeyEnvelopeError::Parsing(
                    "Invalid or missing KDF parameters".to_string(),
                )
            })?;
        let envelope_key = derive_key(&kdf_settings, password)
            .map_err(|_| PasswordProtectedKeyEnvelopeError::Kdf)?;
        let nonce: [u8; crate::xchacha20::NONCE_SIZE] = self
            .cose_encrypt
            .unprotected
            .iv
            .clone()
            .try_into()
            .map_err(|_| PasswordProtectedKeyEnvelopeError::Parsing("Invalid IV".to_string()))?;

        let key_bytes = self
            .cose_encrypt
            .decrypt(&[], |data, aad| {
                xchacha20::decrypt_xchacha20_poly1305(&nonce, &envelope_key, data, aad)
            })
            // If decryption fails, the envelope-key is incorrect and thus the password is incorrect
            // since the KDF parameters & salt are guaranteed to be correct
            .map_err(|_| PasswordProtectedKeyEnvelopeError::WrongPassword)?;

        SymmetricCryptoKey::try_from(
            match ContentFormat::try_from(&self.cose_encrypt.protected.header).map_err(|_| {
                PasswordProtectedKeyEnvelopeError::Parsing("Invalid content format".to_string())
            })? {
                ContentFormat::BitwardenLegacyKey => EncodedSymmetricKey::BitwardenLegacyKey(
                    BitwardenLegacyKeyBytes::from(key_bytes),
                ),
                ContentFormat::CoseKey => {
                    EncodedSymmetricKey::CoseKey(CoseKeyBytes::from(key_bytes))
                }
                _ => {
                    return Err(PasswordProtectedKeyEnvelopeError::Parsing(
                        "Unknown or unsupported content format".to_string(),
                    ));
                }
            },
        )
        .map_err(|_| PasswordProtectedKeyEnvelopeError::Parsing("Failed to decode key".to_string()))
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
        let data = B64::try_from(s).map_err(|_| {
            PasswordProtectedKeyEnvelopeError::Parsing(
                "Invalid PasswordProtectedKeyEnvelope Base64 encoding".to_string(),
            )
        })?;
        Self::try_from(&data.into_bytes()).map_err(|_| {
            PasswordProtectedKeyEnvelopeError::Parsing(
                "Failed to parse PasswordProtectedKeyEnvelope".to_string(),
            )
        })
    }
}

impl<Ids: KeyIds> From<PasswordProtectedKeyEnvelope<Ids>> for String {
    fn from(val: PasswordProtectedKeyEnvelope<Ids>) -> Self {
        let serialized: Vec<u8> = (&val).into();
        B64::from(serialized).to_string()
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
        serializer.serialize_str(&B64::from(serialized).to_string())
    }
}

/// Raw argon2 settings differ from the [crate::keys::Kdf::Argon2id] struct defined for existing
/// master-password unlock. The memory is represented in kibibytes (KiB) instead of mebibytes (MiB),
/// and the salt is a fixed size of 32 bytes, and randomly generated, instead of being derived from
/// the email.
struct Argon2RawSettings {
    iterations: u32,
    /// Memory in KiB
    memory: u32,
    parallelism: u32,
    salt: [u8; ENVELOPE_ARGON2_SALT_SIZE],
}

impl Argon2RawSettings {
    /// Creates default Argon2 settings based on the device. This currently is a static preset
    /// based on the target os
    fn local_kdf_settings() -> Self {
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
        Params::new(
            self.memory,
            self.iterations,
            self.parallelism,
            Some(ENVELOPE_ARGON2_OUTPUT_KEY_SIZE),
        )
        .map_err(|_| PasswordProtectedKeyEnvelopeError::Kdf)
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
                    PasswordProtectedKeyEnvelopeError::Parsing("Invalid Argon2 salt".to_string())
                })?,
        })
    }
}

fn make_salt() -> [u8; ENVELOPE_ARGON2_SALT_SIZE] {
    let mut salt = [0u8; ENVELOPE_ARGON2_SALT_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

fn derive_key(
    argon2_settings: &Argon2RawSettings,
    password: &str,
) -> Result<[u8; ENVELOPE_ARGON2_OUTPUT_KEY_SIZE], PasswordProtectedKeyEnvelopeError> {
    use argon2::*;

    let mut hash = [0u8; ENVELOPE_ARGON2_OUTPUT_KEY_SIZE];
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        argon2_settings.try_into()?,
    )
    .hash_password_into(password.as_bytes(), &argon2_settings.salt, &mut hash)
    .map_err(|_| PasswordProtectedKeyEnvelopeError::Kdf)?;

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
    Parsing(String),
    /// The KDF failed to derive a key, possibly due to invalid parameters or memory allocation
    /// issues
    #[error("Kdf error")]
    Kdf,
    /// There is no key for the provided key id in the key store
    #[error("Key missing error")]
    KeyMissing,
    /// The key store could not be written to, for example due to being read-only
    #[error("Could not write to key store")]
    KeyStore,
}

impl From<CoseExtractError> for PasswordProtectedKeyEnvelopeError {
    fn from(err: CoseExtractError) -> Self {
        let CoseExtractError::MissingValue(label) = err;
        PasswordProtectedKeyEnvelopeError::Parsing(format!("Missing value for {}", label))
    }
}

impl From<TryFromIntError> for PasswordProtectedKeyEnvelopeError {
    fn from(err: TryFromIntError) -> Self {
        PasswordProtectedKeyEnvelopeError::Parsing(format!("Invalid integer: {}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        KeyStore,
        traits::tests::{TestIds, TestSymmKey},
    };

    const TEST_UNSEALED_COSEKEY_ENCODED: &[u8] = &[
        165, 1, 4, 2, 80, 63, 208, 189, 183, 204, 37, 72, 170, 179, 236, 190, 208, 22, 65, 227,
        183, 3, 58, 0, 1, 17, 111, 4, 132, 3, 4, 5, 6, 32, 88, 32, 88, 25, 68, 85, 205, 28, 133,
        28, 90, 147, 160, 145, 48, 3, 178, 184, 30, 11, 122, 132, 64, 59, 51, 233, 191, 117, 159,
        117, 23, 168, 248, 36, 1,
    ];
    const TESTVECTOR_COSEKEY_ENVELOPE: &[u8] = &[
        132, 68, 161, 3, 24, 101, 161, 5, 88, 24, 1, 31, 58, 230, 10, 92, 195, 233, 212, 7, 166,
        252, 67, 115, 221, 58, 3, 191, 218, 188, 181, 192, 28, 11, 88, 84, 141, 183, 137, 167, 166,
        161, 33, 82, 30, 255, 23, 10, 179, 149, 88, 24, 39, 60, 74, 232, 133, 44, 90, 98, 117, 31,
        41, 69, 251, 76, 250, 141, 229, 83, 191, 6, 237, 107, 127, 93, 238, 110, 49, 125, 201, 37,
        162, 120, 157, 32, 116, 195, 208, 143, 83, 254, 223, 93, 97, 158, 0, 24, 95, 197, 249, 35,
        240, 3, 20, 71, 164, 97, 180, 29, 203, 69, 31, 151, 249, 244, 197, 91, 101, 174, 129, 131,
        71, 161, 1, 58, 0, 1, 21, 87, 165, 1, 58, 0, 1, 21, 87, 58, 0, 1, 21, 89, 3, 58, 0, 1, 21,
        90, 26, 0, 1, 0, 0, 58, 0, 1, 21, 91, 4, 58, 0, 1, 21, 88, 80, 165, 253, 56, 243, 255, 54,
        246, 252, 231, 230, 33, 252, 49, 175, 1, 111, 246,
    ];
    const TEST_UNSEALED_LEGACYKEY_ENCODED: &[u8] = &[
        135, 114, 97, 155, 115, 209, 215, 224, 175, 159, 231, 208, 15, 244, 40, 171, 239, 137, 57,
        98, 207, 167, 231, 138, 145, 254, 28, 136, 236, 60, 23, 163, 4, 246, 219, 117, 104, 246,
        86, 10, 152, 52, 90, 85, 58, 6, 70, 39, 111, 128, 93, 145, 143, 180, 77, 129, 178, 242, 82,
        72, 57, 61, 192, 64,
    ];
    const TESTVECTOR_LEGACYKEY_ENVELOPE: &[u8] = &[
        132, 88, 38, 161, 3, 120, 34, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 120,
        46, 98, 105, 116, 119, 97, 114, 100, 101, 110, 46, 108, 101, 103, 97, 99, 121, 45, 107,
        101, 121, 161, 5, 88, 24, 218, 72, 22, 79, 149, 30, 12, 36, 180, 212, 44, 21, 167, 208,
        214, 221, 7, 91, 178, 12, 104, 17, 45, 219, 88, 80, 114, 38, 14, 165, 85, 229, 103, 108,
        17, 175, 41, 43, 203, 175, 119, 125, 227, 127, 163, 214, 213, 138, 12, 216, 163, 204, 38,
        222, 47, 11, 44, 231, 239, 170, 63, 8, 249, 56, 102, 18, 134, 34, 232, 193, 44, 19, 228,
        17, 187, 199, 238, 187, 2, 13, 30, 112, 103, 110, 5, 31, 238, 58, 4, 24, 19, 239, 135, 57,
        206, 190, 144, 83, 128, 204, 59, 155, 21, 80, 180, 34, 129, 131, 71, 161, 1, 58, 0, 1, 21,
        87, 165, 1, 58, 0, 1, 21, 87, 58, 0, 1, 21, 89, 3, 58, 0, 1, 21, 90, 26, 0, 1, 0, 0, 58, 0,
        1, 21, 91, 4, 58, 0, 1, 21, 88, 80, 212, 91, 185, 112, 92, 177, 108, 33, 182, 202, 26, 141,
        11, 133, 95, 235, 246,
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

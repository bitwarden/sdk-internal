use std::marker::PhantomData;

use ciborium::{value::Integer, Value};
use coset::{
    iana::CoapContentFormat, CborSerializable, ContentType, CoseError, Header, HeaderBuilder, Label,
};
use rand::RngCore;
use thiserror::Error;

use crate::{
    cose::{
        ALG_ARGON2ID13, ARGON2_ITERATIONS, ARGON2_MEMORY, ARGON2_PARALLELISM, ARGON2_SALT,
        CONTENT_TYPE_BITWARDEN_LEGACY_KEY,
    },
    xchacha20, BitwardenLegacyKeyBytes, ContentFormat, CoseKeyBytes, EncodedSymmetricKey, KeyIds,
    KeyStoreContext, SymmetricCryptoKey,
};

/// A password-protected key envelope can seal a symmetric key, and protect it with a password. It does so
/// by using a Key Derivation Function (KDF), to increase the difficulty of brute-forcing the password.
///
/// The KDF parameters such as iterations and salt are stored in the key-envelope and do not have to be provided.
pub struct PasswordProtectedKeyEnvelope<Ids: KeyIds> {
    _phantom: PhantomData<Ids>,
    cose_encrypt: coset::CoseEncrypt,
}

impl<Ids: KeyIds> PasswordProtectedKeyEnvelope<Ids> {
    /// Seals a symmetric key with a password, using the current default KDF parameters and a random salt.
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
            .expect("Key should exist in the key store");
        Self::seal_ref(&key_ref, password)
    }

    fn seal_ref(
        key_to_seal: &SymmetricCryptoKey,
        password: &str,
    ) -> Result<Self, PasswordProtectedKeyEnvelopeError> {
        let kdf = Argon2RawSettings {
            iterations: 3,
            memory: 64 * 1024, // 64 MiB
            parallelism: 4,
            salt: make_salt(),
        };
        Self::seal_ref_with_settings(key_to_seal, password, &kdf)
    }

    fn seal_ref_with_settings(
        key_to_seal: &SymmetricCryptoKey,
        password: &str,
        kdf_settings: &Argon2RawSettings,
    ) -> Result<Self, PasswordProtectedKeyEnvelopeError> {
        // Cose does not yet have a standardized way to protect a key using a password.
        // This implements content encryption using direct encryption with a KDF derived key, similar to
        // "Direct Key with KDF". The KDF settings are placed in a single recipient struct.

        // The envelope key is directly derived from the KDF and used as the key to encrypt the key that should
        // be sealed.
        let envelope_key = derive_key(kdf_settings, password)
            .map_err(|_| PasswordProtectedKeyEnvelopeError::KdfError)?;

        #[allow(deprecated)]
        let (content_format, key_to_seal_bytes) = match key_to_seal.to_encoded_raw() {
            EncodedSymmetricKey::BitwardenLegacyKey(key_bytes) => {
                (ContentFormat::BitwardenLegacyKey, key_bytes.to_vec())
            }
            EncodedSymmetricKey::CoseKey(key_bytes) => (ContentFormat::CoseKey, key_bytes.to_vec()),
        };

        let mut nonce = [0u8; crate::xchacha20::NONCE_SIZE];
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

    /// Unseals a symmetric key from the password-protected envelope, and stores it in the key store context.
    pub fn unseal(
        &self,
        target_keyslot: Ids::Symmetric,
        password: &str,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Symmetric, PasswordProtectedKeyEnvelopeError> {
        let key = self.unseal_ref(password)?;
        #[allow(deprecated)]
        ctx.set_symmetric_key(target_keyslot, key).unwrap();
        Ok(target_keyslot)
    }

    fn unseal_ref(
        &self,
        password: &str,
    ) -> Result<SymmetricCryptoKey, PasswordProtectedKeyEnvelopeError> {
        // There must be exactly one recipient in the COSE Encrypt object, which contains the KDF parameters.
        if self.cose_encrypt.recipients.len() != 1 {
            return Err(PasswordProtectedKeyEnvelopeError::ParsingError(
                "Invalid number of recipients".to_string(),
            ));
        }

        let recipient = self
            .cose_encrypt
            .recipients
            .get(0)
            .expect("Recipient should exist");
        if recipient.protected.header.alg != Some(coset::Algorithm::PrivateUse(ALG_ARGON2ID13)) {
            return Err(PasswordProtectedKeyEnvelopeError::ParsingError(
                "Unknown or unsupported KDF algorithm".to_string(),
            ));
        }

        let kdf_settings: Argon2RawSettings =
            recipient.unprotected.clone().try_into().map_err(|_| {
                PasswordProtectedKeyEnvelopeError::ParsingError(
                    "Invalid or missing KDF parameters".to_string(),
                )
            })?;
        let envelope_key = derive_key(&kdf_settings, password)
            .map_err(|_| PasswordProtectedKeyEnvelopeError::KdfError)?;

        let key_bytes = self
            .cose_encrypt
            .decrypt(&[], |data, aad| {
                xchacha20::decrypt_xchacha20_poly1305(
                    &self.cose_encrypt.unprotected.iv.clone().try_into().unwrap(),
                    &envelope_key,
                    data,
                    aad,
                )
            })
            .map_err(|_| PasswordProtectedKeyEnvelopeError::WrongPassword)?;

        let key = SymmetricCryptoKey::try_from(
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
        .unwrap();
        Ok(key)
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

impl<Ids: KeyIds> TryInto<Vec<u8>> for &PasswordProtectedKeyEnvelope<Ids> {
    type Error = CoseError;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        self.cose_encrypt.clone().to_vec()
    }
}

impl<Ids: KeyIds> TryFrom<&Vec<u8>> for PasswordProtectedKeyEnvelope<Ids> {
    type Error = CoseError;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        let cose_encrypt = coset::CoseEncrypt::from_slice(&value)?;
        Ok(PasswordProtectedKeyEnvelope {
            _phantom: PhantomData,
            cose_encrypt,
        })
    }
}

/// Raw argon2 settings differ from the KDF struct defined for existing master-password unlock.
/// The memory is represented in kibibytes (KiB) instead of mebibytes (MiB), and the salt is a fixed size of 32 bytes,
/// and randomly generated, instead of being derived from the email.
struct Argon2RawSettings {
    iterations: u32,
    memory: u32,
    parallelism: u32,
    salt: [u8; 32],
}

impl Into<Header> for &Argon2RawSettings {
    fn into(self) -> Header {
        let builder = HeaderBuilder::new()
            .value(ARGON2_ITERATIONS, Integer::from(self.iterations).into())
            .value(ARGON2_MEMORY, Integer::from(self.memory).into())
            .value(ARGON2_PARALLELISM, Integer::from(self.parallelism).into())
            .value(ARGON2_SALT, Value::from(self.salt.to_vec()));

        let mut header = builder.build();
        header.alg = Some(coset::Algorithm::PrivateUse(ALG_ARGON2ID13));
        header
    }
}

impl TryInto<Argon2RawSettings> for Header {
    type Error = PasswordProtectedKeyEnvelopeError;

    fn try_into(self) -> Result<Argon2RawSettings, PasswordProtectedKeyEnvelopeError> {
        let iterations = self
            .rest
            .iter()
            .find_map(|(label, value)| match (label, value) {
                (Label::Int(ARGON2_ITERATIONS), ciborium::Value::Integer(value)) => Some(value),
                _ => None,
            })
            .ok_or(PasswordProtectedKeyEnvelopeError::ParsingError(
                "Missing Argon2 iterations".to_string(),
            ))?;
        let memory = self
            .rest
            .iter()
            .find_map(|(label, value)| match (label, value) {
                (Label::Int(ARGON2_MEMORY), ciborium::Value::Integer(value)) => Some(value),
                _ => None,
            })
            .ok_or(PasswordProtectedKeyEnvelopeError::ParsingError(
                "Missing Argon2 memory".to_string(),
            ))?;
        let parallelism = self
            .rest
            .iter()
            .find_map(|(label, value)| match (label, value) {
                (Label::Int(ARGON2_PARALLELISM), ciborium::Value::Integer(value)) => Some(value),
                _ => None,
            })
            .ok_or(PasswordProtectedKeyEnvelopeError::ParsingError(
                "Missing Argon2 parallelism".to_string(),
            ))?;
        let salt: [u8; 32] = self
            .rest
            .iter()
            .find_map(|(label, value)| match (label, value) {
                (Label::Int(ARGON2_SALT), ciborium::Value::Bytes(value)) if value.len() == 32 => {
                    Some(value.as_slice().try_into().unwrap())
                }
                _ => None,
            })
            .ok_or(PasswordProtectedKeyEnvelopeError::ParsingError(
                "Missing or invalid Argon2 salt".to_string(),
            ))?;

        Ok(Argon2RawSettings {
            iterations: i128::from(*iterations).try_into().unwrap(),
            memory: i128::from(*memory).try_into().unwrap(),
            parallelism: i128::from(*parallelism).try_into().unwrap(),
            salt,
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
) -> Result<[u8; 32], crate::CryptoError> {
    use argon2::*;

    let params = Params::new(
        argon2_settings.memory,
        argon2_settings.iterations,
        argon2_settings.parallelism,
        Some(32),
    )?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut hash = [0u8; 32];
    argon.hash_password_into(password.as_bytes(), &argon2_settings.salt, &mut hash)?;
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
    /// The KDF failed to derive a key, possibly due to invalid parameters or memory allocation issues
    #[error("Kdf error")]
    KdfError,
}

#[cfg(test)]
mod tests {
    use crate::{
        traits::tests::{TestIds, TestSymmKey},
        KeyStore,
    };

    use super::*;

    #[test]
    fn test_make_envelope() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx: KeyStoreContext<'_, TestIds> = key_store.context_mut();
        let test_key = ctx.make_cose_symmetric_key(TestSymmKey::A(0)).unwrap();

        let password = "test_password";

        // Seal the key with a password
        let envelope = PasswordProtectedKeyEnvelope::seal(test_key, password, &ctx).unwrap();
        let serialized: Vec<u8> = (&envelope).try_into().unwrap();

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
        let serialized: Vec<u8> = (&envelope).try_into().unwrap();

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
            PasswordProtectedKeyEnvelope::try_from(&(&envelope).try_into().unwrap()).unwrap();
        assert!(matches!(
            deserialized.unseal(TestSymmKey::A(1), wrong_password, &mut ctx),
            Err(PasswordProtectedKeyEnvelopeError::WrongPassword)
        ));
    }
}

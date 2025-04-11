use std::pin::Pin;

use base64::{engine::general_purpose::STANDARD, Engine};
use generic_array::{typenum::U32, GenericArray};
use rand::Rng;
use zeroize::{Zeroize, Zeroizing};

use super::utils::stretch_key;
use crate::{
    CryptoError, EncString, KeyDecryptable, Result, SymmetricCryptoKey, UserKey,
};

/// Key connector key
///
/// Randomly generated and stored in keyconnector, used to protect the [UserKey].
pub struct KeyConnectorKey(Pin<Box<GenericArray<u8, U32>>>);

impl KeyConnectorKey {
    pub fn generate(mut rng: impl rand::RngCore) -> Self {
        let mut key = Box::pin(GenericArray::<u8, U32>::default());
        rng.fill(key.as_mut_slice());
        Self(key)
    }

    /// Generate a new random user key and encrypt it with the master key.
    pub fn make_user_key(&self) -> Result<(UserKey, EncString)> {
        make_user_key(&mut rand::thread_rng(), self)
    }

    /// Decrypt the users user key
    pub fn decrypt_user_key(&self, user_key: EncString) -> Result<SymmetricCryptoKey> {
        decrypt_user_key(&self.0, user_key)
    }

    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.0.as_slice())
    }
}

impl TryFrom<&mut [u8]> for KeyConnectorKey {
    type Error = CryptoError;

    fn try_from(value: &mut [u8]) -> Result<Self> {
        if value.len() != 32 {
            value.zeroize();
            return Err(CryptoError::InvalidKey);
        }

        let key = Box::pin(GenericArray::<u8, U32>::default());
        value.zeroize();
        Ok(Self(key))
    }
}

/// Helper function to encrypt a user key with a master or pin key.
fn encrypt_user_key(
    key_connector_key: &KeyConnectorKey,
    user_key: &SymmetricCryptoKey,
) -> Result<EncString> {
    let stretched_key_connector_key = stretch_key(&key_connector_key.0)?;
    let user_key_bytes = Zeroizing::new(user_key.to_encoded());
    EncString::encrypt_aes256_hmac(&user_key_bytes, &stretched_key_connector_key)
}

/// Helper function to decrypt a user key with a master or pin key or key-connector-key.
fn decrypt_user_key(
    key: &Pin<Box<GenericArray<u8, U32>>>,
    user_key: EncString,
) -> Result<SymmetricCryptoKey> {
    let mut dec: Vec<u8> = match user_key {
        // Legacy. user_keys were encrypted using `AesCbc256_B64` a long time ago. We've since
        // moved to using `AesCbc256_HmacSha256_B64`. However, we still need to support
        // decrypting these old keys.
        EncString::AesCbc256_B64 { .. } => {
            let legacy_key = SymmetricCryptoKey::Aes256CbcKey(super::Aes256CbcKey {
                enc_key: Box::pin(GenericArray::clone_from_slice(key)),
            });
            user_key.decrypt_with_key(&legacy_key)?
        }
        EncString::AesCbc256_HmacSha256_B64 { .. } => {
            let stretched_key = SymmetricCryptoKey::Aes256CbcHmacKey(stretch_key(key)?);
            user_key.decrypt_with_key(&stretched_key)?
        }
        EncString::XChaCha20_Poly1305_Cose_B64 { .. } => {
            return Err(CryptoError::OperationNotSupported(
                crate::error::UnsupportedOperation::EncryptionNotImplementedForKey,
            ));
        }
    };

    SymmetricCryptoKey::try_from(dec.as_mut_slice())
}

/// Generate a new random user key and encrypt it with the master key.
fn make_user_key(rng: impl rand::RngCore, key_connector_key: &KeyConnectorKey) -> Result<(UserKey, EncString)> {
    let user_key = SymmetricCryptoKey::generate_internal(rng, false);
    let protected = encrypt_user_key(&key_connector_key, &user_key)?;
    Ok((UserKey::new(user_key), protected))
}

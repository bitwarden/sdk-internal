use std::pin::Pin;

use bitwarden_encoding::B64;
use generic_array::GenericArray;
use rand::Rng;
use typenum::U32;

use crate::{
    BitwardenLegacyKeyBytes, CryptoError, EncString, KeyDecryptable, SymmetricCryptoKey,
    keys::utils::stretch_key,
};

/// Key connector key, used to protect the user key.
#[derive(Clone)]
pub struct KeyConnectorKey(pub(super) Pin<Box<GenericArray<u8, U32>>>);

impl KeyConnectorKey {
    /// Make a new random key for KeyConnector.
    pub fn make() -> Self {
        let mut rng = rand::thread_rng();
        let mut key = Box::pin(GenericArray::<u8, U32>::default());

        rng.fill(key.as_mut_slice());
        KeyConnectorKey(key)
    }

    #[allow(missing_docs)]
    pub fn to_base64(&self) -> B64 {
        B64::from(self.0.as_slice())
    }

    /// Wraps the user key with this key connector key.
    pub fn encrypt_user_key(
        &self,
        user_key: &SymmetricCryptoKey,
    ) -> crate::error::Result<EncString> {
        let stretched_key = stretch_key(&self.0)?;
        let user_key_bytes = user_key.to_encoded();
        EncString::encrypt_aes256_hmac(user_key_bytes.as_ref(), &stretched_key)
    }

    /// Unwraps the user key with this key connector key.
    pub fn decrypt_user_key(
        &self,
        user_key: EncString,
    ) -> crate::error::Result<SymmetricCryptoKey> {
        let dec: Vec<u8> = match user_key {
            // Legacy. user_keys were encrypted using `Aes256Cbc_B64` a long time ago. We've since
            // moved to using `Aes256Cbc_HmacSha256_B64`. However, we still need to support
            // decrypting these old keys.
            EncString::Aes256Cbc_B64 { .. } => {
                let legacy_key = SymmetricCryptoKey::Aes256CbcKey(super::Aes256CbcKey {
                    enc_key: Box::pin(GenericArray::clone_from_slice(&self.0)),
                });
                user_key.decrypt_with_key(&legacy_key)?
            }
            EncString::Aes256Cbc_HmacSha256_B64 { .. } => {
                let stretched_key = SymmetricCryptoKey::Aes256CbcHmacKey(stretch_key(&self.0)?);
                user_key.decrypt_with_key(&stretched_key)?
            }
            _ => {
                return Err(CryptoError::OperationNotSupported(
                    crate::error::UnsupportedOperationError::EncryptionNotImplementedForKey,
                ));
            }
        };

        SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(dec))
    }
}

impl std::fmt::Debug for KeyConnectorKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyConnectorKey").finish()
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_encoding::B64;
    use coset::iana::KeyOperation;
    use rand_chacha::rand_core::SeedableRng;

    use super::KeyConnectorKey;
    use crate::{BitwardenLegacyKeyBytes, SymmetricCryptoKey, UserKey};

    const KEY_CONNECTOR_KEY_BYTES: [u8; 32] = [
        31, 79, 104, 226, 150, 71, 177, 90, 194, 80, 172, 209, 17, 129, 132, 81, 138, 167, 69, 167,
        254, 149, 2, 27, 39, 197, 64, 42, 22, 195, 86, 75,
    ];

    #[test]
    fn test_make_two_different_keys() {
        let key1 = KeyConnectorKey::make();
        let key2 = KeyConnectorKey::make();
        assert_ne!(key1.0.as_slice(), key2.0.as_slice());
    }

    #[test]
    fn test_to_base64() {
        let key = KeyConnectorKey(Box::pin(KEY_CONNECTOR_KEY_BYTES.into()));

        assert_eq!(
            "H09o4pZHsVrCUKzREYGEUYqnRaf+lQIbJ8VAKhbDVks=",
            key.to_base64().to_string()
        );
    }

    #[test]
    fn test_encrypt_decrypt_user_key_aes256_cbc_hmac() {
        let rng = rand_chacha::ChaCha8Rng::from_seed([0u8; 32]);

        let key_connector_key = KeyConnectorKey(Box::pin(KEY_CONNECTOR_KEY_BYTES.into()));

        let user_key = SymmetricCryptoKey::make_aes256_cbc_hmac_key_internal(rng);
        let wrapped_user_key = key_connector_key.encrypt_user_key(&user_key).unwrap();
        let user_key = UserKey::new(user_key);

        let decrypted_user_key = key_connector_key
            .decrypt_user_key(wrapped_user_key)
            .unwrap();

        let SymmetricCryptoKey::Aes256CbcHmacKey(user_key_unwrapped) = &decrypted_user_key else {
            panic!("User key is not an Aes256CbcHmacKey");
        };

        assert_eq!(
            user_key_unwrapped.enc_key.as_slice(),
            [
                62, 0, 239, 47, 137, 95, 64, 214, 127, 91, 184, 232, 31, 9, 165, 161, 44, 132, 14,
                195, 206, 154, 127, 59, 24, 27, 225, 136, 239, 113, 26, 30
            ]
        );
        assert_eq!(
            user_key_unwrapped.mac_key.as_slice(),
            [
                152, 76, 225, 114, 185, 33, 111, 65, 159, 68, 83, 103, 69, 109, 86, 25, 49, 74, 66,
                163, 218, 134, 176, 1, 56, 123, 253, 184, 14, 12, 254, 66
            ]
        );

        assert_eq!(
            decrypted_user_key, user_key.0,
            "Decrypted key doesn't match user key"
        );
    }

    #[test]
    fn test_encrypt_decrypt_user_key_xchacha20_poly1305() {
        let key_connector_key = KeyConnectorKey(Box::pin(KEY_CONNECTOR_KEY_BYTES.into()));

        let user_key_b64: B64 = "pQEEAlDib+JxbqMBlcd3KTUesbufAzoAARFvBIQDBAUGIFggt79surJXmqhPhYuuqi9ZyPfieebmtw2OsmN5SDrb4yUB".parse()
            .unwrap();
        let user_key =
            SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(&user_key_b64)).unwrap();
        let wrapped_user_key = key_connector_key.encrypt_user_key(&user_key).unwrap();
        let user_key = UserKey::new(user_key);

        let decrypted_user_key = key_connector_key
            .decrypt_user_key(wrapped_user_key)
            .unwrap();

        let SymmetricCryptoKey::XChaCha20Poly1305Key(user_key_unwrapped) = &decrypted_user_key
        else {
            panic!("User key is not an XChaCha20Poly1305Key");
        };

        assert_eq!(
            user_key_unwrapped.enc_key.as_slice(),
            [
                183, 191, 108, 186, 178, 87, 154, 168, 79, 133, 139, 174, 170, 47, 89, 200, 247,
                226, 121, 230, 230, 183, 13, 142, 178, 99, 121, 72, 58, 219, 227, 37
            ]
        );
        assert_eq!(
            user_key_unwrapped.key_id.as_slice(),
            [
                226, 111, 226, 113, 110, 163, 1, 149, 199, 119, 41, 53, 30, 177, 187, 159
            ]
        );
        assert_eq!(
            user_key_unwrapped.supported_operations,
            [
                KeyOperation::Encrypt,
                KeyOperation::Decrypt,
                KeyOperation::WrapKey,
                KeyOperation::UnwrapKey
            ]
        );

        assert_eq!(
            decrypted_user_key, user_key.0,
            "Decrypted key doesn't match user key"
        );
    }
}

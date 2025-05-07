use std::str::FromStr;

use bitwarden_crypto::{
    CryptoError, EncString, Kdf, KeyDecryptable, KeyEncryptable, MasterKey, SymmetricCryptoKey,
};
use wasm_bindgen::prelude::*;

/// This module represents a stopgap solution to provide access to primitive crypto functions for JS
/// clients. It is not intended to be used outside of the JS clients and this pattern should not be
/// proliferated. It is necessary because we want to use SDK crypto prior to the SDK being fully
/// responsible for state and keys.
#[wasm_bindgen]
pub struct PureCrypto {}

// Encryption
#[wasm_bindgen]
impl PureCrypto {
    /// DEPRECATED: Use `symmetric_decrypt_string` instead.
    /// Cleanup ticket: <https://bitwarden.atlassian.net/browse/PM-21247>
    pub fn symmetric_decrypt(enc_string: String, key: Vec<u8>) -> Result<String, CryptoError> {
        Self::symmetric_decrypt_string(enc_string, key)
    }

    pub fn symmetric_decrypt_string(
        enc_string: String,
        key: Vec<u8>,
    ) -> Result<String, CryptoError> {
        EncString::from_str(&enc_string)?.decrypt_with_key(&SymmetricCryptoKey::try_from(key)?)
    }

    pub fn symmetric_decrypt_bytes(
        enc_string: String,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        EncString::from_str(&enc_string)?.decrypt_with_key(&SymmetricCryptoKey::try_from(key)?)
    }

    /// DEPRECATED: Use `symmetric_decrypt_filedata` instead.
    /// Cleanup ticket: <https://bitwarden.atlassian.net/browse/PM-21247>
    pub fn symmetric_decrypt_array_buffer(
        enc_bytes: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        Self::symmetric_decrypt_filedata(enc_bytes, key)
    }

    pub fn symmetric_decrypt_filedata(
        enc_bytes: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        EncString::from_buffer(&enc_bytes)?.decrypt_with_key(&SymmetricCryptoKey::try_from(key)?)
    }

    pub fn symmetric_encrypt_string(plain: String, key: Vec<u8>) -> Result<String, CryptoError> {
        plain
            .encrypt_with_key(&SymmetricCryptoKey::try_from(key)?)
            .map(|enc| enc.to_string())
    }

    pub fn symmetric_encrypt_bytes(plain: Vec<u8>, key: Vec<u8>) -> Result<String, CryptoError> {
        plain
            .encrypt_with_key(&SymmetricCryptoKey::try_from(key)?)
            .map(|enc| enc.to_string())
    }

    pub fn symmetric_encrypt_filedata(
        plain: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        plain
            .encrypt_with_key(&SymmetricCryptoKey::try_from(key)?)?
            .to_buffer()
    }

    // Userkey encryption with password
    pub fn decrypt_user_key_with_master_password(
        encrypted_user_key: String,
        master_password: String,
        email: String,
        kdf: Kdf,
    ) -> Result<Vec<u8>, CryptoError> {
        let master_key = MasterKey::derive(master_password.as_str(), email.as_str(), &kdf)?;
        let encrypted_user_key = EncString::from_str(&encrypted_user_key)?;
        let result = master_key
            .decrypt_user_key(encrypted_user_key)
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(result.to_encoded())
    }

    pub fn encrypt_user_key_with_master_password(
        user_key: Vec<u8>,
        master_password: String,
        email: String,
        kdf: Kdf,
    ) -> Result<String, CryptoError> {
        let master_key = MasterKey::derive(master_password.as_str(), email.as_str(), &kdf)?;
        let user_key = SymmetricCryptoKey::try_from(user_key)?;
        let result = master_key.encrypt_user_key(&user_key)?;
        Ok(result.to_string())
    }

    // Generate userkey
    pub fn generate_user_key_aes256_cbc_hmac() -> Vec<u8> {
        SymmetricCryptoKey::make_aes256_cbc_hmac_key().to_encoded()
    }

    pub fn generate_user_key_xchacha20_poly1305() -> Vec<u8> {
        SymmetricCryptoKey::make_xchacha20_poly1305_key().to_encoded()
    }
}

#[cfg(test)]
mod tests {
    use std::{num::NonZero, str::FromStr};

    use bitwarden_crypto::EncString;

    use super::*;

    const KEY: &[u8] = &[
        81, 142, 1, 228, 222, 3, 3, 133, 34, 176, 35, 66, 150, 6, 109, 70, 190, 149, 47, 47, 89,
        23, 144, 87, 92, 46, 220, 13, 148, 106, 162, 234, 202, 139, 136, 33, 16, 200, 8, 73, 176,
        172, 185, 187, 224, 10, 65, 223, 228, 54, 92, 181, 8, 213, 162, 221, 117, 254, 245, 111,
        55, 211, 77, 29,
    ];

    const ENCRYPTED: &str = "2.Dh7AFLXR+LXcxUaO5cRjpg==|uXyhubjAoNH8lTdy/zgJDQ==|cHEMboj0MYsU5yDRQ1rLCgxcjNbKRc1PWKuv8bpU5pM=";
    const DECRYPTED: &str = "test";
    const DECRYPTED_BYTES: &[u8] = b"test";
    const ENCRYPTED_BYTES: &[u8] = &[
        2, 209, 195, 115, 49, 205, 253, 128, 162, 169, 246, 175, 217, 144, 73, 108, 191, 27, 113,
        69, 55, 94, 142, 62, 129, 204, 173, 130, 37, 42, 97, 209, 25, 192, 64, 126, 112, 139, 248,
        2, 89, 112, 178, 83, 25, 77, 130, 187, 127, 85, 179, 211, 159, 186, 111, 44, 109, 211, 18,
        120, 104, 144, 4, 76, 3,
    ];

    #[test]
    fn test_symmetric_decrypt() {
        let enc_string = EncString::from_str(ENCRYPTED).unwrap();

        let result = PureCrypto::symmetric_decrypt_string(enc_string.to_string(), KEY.to_vec());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), DECRYPTED);
    }

    #[test]
    fn test_symmetric_encrypt() {
        let result = PureCrypto::symmetric_encrypt_string(DECRYPTED.to_string(), KEY.to_vec());
        assert!(result.is_ok());
        // Cannot test encrypted string content because IV is unique per encryption
    }

    #[test]
    fn test_symmetric_string_round_trip() {
        let encrypted =
            PureCrypto::symmetric_encrypt_string(DECRYPTED.to_string(), KEY.to_vec()).unwrap();
        let decrypted =
            PureCrypto::symmetric_decrypt_string(encrypted.clone(), KEY.to_vec()).unwrap();
        assert_eq!(decrypted, DECRYPTED);
    }

    #[test]
    fn test_symmetric_bytes_round_trip() {
        let encrypted =
            PureCrypto::symmetric_encrypt_bytes(DECRYPTED.as_bytes().to_vec(), KEY.to_vec())
                .unwrap();
        let decrypted =
            PureCrypto::symmetric_decrypt_bytes(encrypted.clone(), KEY.to_vec()).unwrap();
        assert_eq!(decrypted, DECRYPTED.as_bytes().to_vec());
    }

    #[test]
    fn test_symmetric_decrypt_array_buffer() {
        let result = PureCrypto::symmetric_decrypt_filedata(ENCRYPTED_BYTES.to_vec(), KEY.to_vec());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), DECRYPTED_BYTES);
    }

    #[test]
    fn test_symmetric_encrypt_to_array_buffer() {
        let result = PureCrypto::symmetric_encrypt_filedata(DECRYPTED_BYTES.to_vec(), KEY.to_vec());
        assert!(result.is_ok());
        // Cannot test encrypted string content because IV is unique per encryption
    }

    #[test]
    fn test_symmetric_filedata_round_trip() {
        let encrypted =
            PureCrypto::symmetric_encrypt_filedata(DECRYPTED_BYTES.to_vec(), KEY.to_vec()).unwrap();
        let decrypted =
            PureCrypto::symmetric_decrypt_filedata(encrypted.clone(), KEY.to_vec()).unwrap();
        assert_eq!(decrypted, DECRYPTED_BYTES);
    }

    #[test]
    fn test_make_aes256_cbc_hmac_key() {
        let key = PureCrypto::generate_user_key_aes256_cbc_hmac();
        assert_eq!(key.len(), 64);
    }

    #[test]
    fn test_make_xchacha20_poly1305_key() {
        let key = PureCrypto::generate_user_key_xchacha20_poly1305();
        assert!(key.len() > 64);
    }

    #[test]
    fn roundtrip_encrypt_user_key_with_master_password() {
        let master_password = "test";
        let email = "test@example.com";
        let kdf = Kdf::PBKDF2 {
            iterations: NonZero::try_from(600000).unwrap(),
        };
        let user_key = PureCrypto::generate_user_key_aes256_cbc_hmac();
        let encrypted_user_key = PureCrypto::encrypt_user_key_with_master_password(
            user_key.clone(),
            master_password.to_string(),
            email.to_string(),
            kdf.clone(),
        )
        .unwrap();
        let decrypted_user_key = PureCrypto::decrypt_user_key_with_master_password(
            encrypted_user_key,
            master_password.to_string(),
            email.to_string(),
            kdf,
        )
        .unwrap();
        assert_eq!(user_key, decrypted_user_key);
    }
}

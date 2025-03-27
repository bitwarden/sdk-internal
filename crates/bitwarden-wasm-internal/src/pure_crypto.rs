use std::str::FromStr;

use bitwarden_crypto::{
    ContentFormat, CryptoError, EncString, Kdf, KeyDecryptable, KeyEncryptable, MasterKey,
    SymmetricCryptoKey,
};
use wasm_bindgen::prelude::*;

/// This module represents a stopgap solution to provide access to primitive crypto functions for JS
/// clients. It is not intended to be used outside of the JS clients and this pattern should not be
/// proliferated. It is necessary because we want to use SDK crypto prior to the SDK being fully
/// responsible for state and keys.
#[wasm_bindgen]
pub struct PureCrypto {}

#[wasm_bindgen]
impl PureCrypto {
    pub fn symmetric_decrypt(enc_string: String, key_b64: Vec<u8>) -> Result<String, CryptoError> {
        let enc_string = EncString::from_str(&enc_string)?;
        let key = SymmetricCryptoKey::try_from(key_b64)?;
        enc_string.decrypt_with_key(&key)
    }

    pub fn symmetric_decrypt_to_bytes(
        enc_string: String,
        key_b64: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let enc_string = EncString::from_str(&enc_string)?;
        let key = SymmetricCryptoKey::try_from(key_b64)?;
        enc_string.decrypt_with_key(&key)
    }

    pub fn symmetric_decrypt_array_buffer(
        enc_bytes: Vec<u8>,
        key_b64: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let enc_string = EncString::from_buffer(&enc_bytes)?;
        let key = SymmetricCryptoKey::try_from(key_b64)?;
        enc_string.decrypt_with_key(&key)
    }

    pub fn symmetric_encrypt(
        plain: Vec<u8>,
        key_b64: Vec<u8>,
        content_format: ContentFormat,
    ) -> Result<String, CryptoError> {
        let key = SymmetricCryptoKey::try_from(key_b64)?;
        Ok(plain.encrypt_with_key(&key, content_format)?.to_string())
    }

    pub fn symmetric_encrypt_to_array_buffer(
        plain: Vec<u8>,
        key_b64: Vec<u8>,
        content_format: ContentFormat,
    ) -> Result<Vec<u8>, CryptoError> {
        let key = SymmetricCryptoKey::try_from(key_b64)?;
        plain.encrypt_with_key(&key, content_format)?.to_buffer()
    }

    pub fn decrypt_userkey_with_masterpassword(
        encrypted_userkey: String,
        master_password: String,
        email: String,
        kdf: Kdf,
    ) -> Result<Vec<u8>, CryptoError> {
        let masterkey = MasterKey::derive(master_password.as_str(), email.as_str(), &kdf)?;
        let encrypted_userkey = EncString::from_str(&encrypted_userkey)?;
        let result = masterkey
            .decrypt_user_key(encrypted_userkey)
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(result.to_encoded())
    }

    pub fn encrypt_userkey_with_masterpassword(
        userkey: Vec<u8>,
        master_password: String,
        email: String,
        kdf: Kdf,
    ) -> Result<String, CryptoError> {
        let masterkey = MasterKey::derive(master_password.as_str(), email.as_str(), &kdf)?;
        let userkey = SymmetricCryptoKey::try_from(userkey)?;
        let result = masterkey.encrypt_user_key(&userkey)?;
        Ok(result.to_string())
    }

    pub fn generate_userkey(use_xchacha20: bool) -> Result<Vec<u8>, CryptoError> {
        let key = if !use_xchacha20 {
            SymmetricCryptoKey::generate()
        } else {
            SymmetricCryptoKey::generate_xchacha20()
        };
        Ok(key.to_encoded())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitwarden_crypto::EncString;

    use super::*;

    const KEY_B64: &str =
        "UY4B5N4DA4UisCNClgZtRr6VLy9ZF5BXXC7cDZRqourKi4ghEMgISbCsubvgCkHf5DZctQjVot11/vVvN9NNHQ==";
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

        let result =
            PureCrypto::symmetric_decrypt(enc_string.to_string(), KEY_B64.as_bytes().to_vec());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), DECRYPTED);
    }

    #[test]
    fn test_symmetric_encrypt() {
        let result = PureCrypto::symmetric_encrypt(
            DECRYPTED.as_bytes().to_vec(),
            KEY_B64.as_bytes().to_vec(),
            ContentFormat::Utf8,
        );
        assert!(result.is_ok());
        // Cannot test encrypted string content because IV is unique per encryption
    }

    #[test]
    fn test_symmetric_round_trip() {
        let encrypted = PureCrypto::symmetric_encrypt(
            DECRYPTED.as_bytes().to_vec(),
            KEY_B64.as_bytes().to_vec(),
            ContentFormat::Utf8,
        )
        .unwrap();
        let decrypted =
            PureCrypto::symmetric_decrypt(encrypted.clone(), KEY_B64.as_bytes().to_vec()).unwrap();
        assert_eq!(decrypted, DECRYPTED);
    }

    #[test]
    fn test_symmetric_decrypt_array_buffer() {
        let result = PureCrypto::symmetric_decrypt_array_buffer(
            ENCRYPTED_BYTES.to_vec(),
            KEY_B64.as_bytes().to_vec(),
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), DECRYPTED_BYTES);
    }

    #[test]
    fn test_symmetric_encrypt_to_array_buffer() {
        let result = PureCrypto::symmetric_encrypt_to_array_buffer(
            DECRYPTED_BYTES.to_vec(),
            KEY_B64.as_bytes().to_vec(),
            ContentFormat::Utf8,
        );
        assert!(result.is_ok());
        // Cannot test encrypted string content because IV is unique per encryption
    }

    #[test]
    fn test_symmetric_buffer_round_trip() {
        let encrypted = PureCrypto::symmetric_encrypt_to_array_buffer(
            DECRYPTED_BYTES.to_vec(),
            KEY_B64.as_bytes().to_vec(),
            ContentFormat::Utf8,
        )
        .unwrap();
        let decrypted = PureCrypto::symmetric_decrypt_array_buffer(
            encrypted.clone(),
            KEY_B64.as_bytes().to_vec(),
        )
        .unwrap();
        assert_eq!(decrypted, DECRYPTED_BYTES);
    }
}

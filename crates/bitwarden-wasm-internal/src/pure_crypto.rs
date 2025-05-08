use std::str::FromStr;

use bitwarden_core::key_management::{KeyIds, SymmetricKeyId};
use bitwarden_crypto::{
    AsymmetricCryptoKey, AsymmetricPublicCryptoKey, CryptoError, Decryptable, EncString,
    Encryptable, Kdf, KeyDecryptable, KeyEncryptable, KeyStore, MasterKey, SymmetricCryptoKey,
    UnsignedSharedKey,
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

    // Key wrap
    pub fn wrap_symmetric_key(
        key_to_be_wrapped: Vec<u8>,
        wrapping_key: Vec<u8>,
    ) -> Result<String, CryptoError> {
        let tmp_store: KeyStore<KeyIds> = KeyStore::default();
        let mut context = tmp_store.context();
        #[allow(deprecated)]
        context.set_symmetric_key(
            SymmetricKeyId::Local("wrapping_key"),
            SymmetricCryptoKey::try_from(wrapping_key)?,
        )?;
        #[allow(deprecated)]
        context.set_symmetric_key(
            SymmetricKeyId::Local("key_to_wrap"),
            SymmetricCryptoKey::try_from(key_to_be_wrapped)?,
        )?;
        // Note: The order of arguments is different here, and should probably be refactored
        Ok(context
            .wrap_symmetric_key(
                SymmetricKeyId::Local("wrapping_key"),
                SymmetricKeyId::Local("key_to_wrap"),
            )?
            .to_string())
    }

    pub fn unwrap_symmetric_key(
        wrapped_key: String,
        wrapping_key: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let tmp_store: KeyStore<KeyIds> = KeyStore::default();
        let mut context = tmp_store.context();
        #[allow(deprecated)]
        context.set_symmetric_key(
            SymmetricKeyId::Local("wrapping_key"),
            SymmetricCryptoKey::try_from(wrapping_key)?,
        )?;
        // Note: The order of arguments is different here, and should probably be refactored
        context.unwrap_symmetric_key(
            SymmetricKeyId::Local("wrapping_key"),
            SymmetricKeyId::Local("wrapped_key"),
            &EncString::from_str(wrapped_key.as_str())?,
        )?;
        #[allow(deprecated)]
        let key = context.dangerous_get_symmetric_key(SymmetricKeyId::Local("wrapped_key"))?;
        Ok(key.to_encoded())
    }

    pub fn wrap_encapsulation_key(
        encapsulation_key: Vec<u8>,
        wrapping_key: Vec<u8>,
    ) -> Result<String, CryptoError> {
        let tmp_store: KeyStore<KeyIds> = KeyStore::default();
        let mut context = tmp_store.context();
        #[allow(deprecated)]
        context.set_symmetric_key(
            SymmetricKeyId::Local("wrapping_key"),
            SymmetricCryptoKey::try_from(wrapping_key)?,
        )?;
        // Note: The order of arguments is different here, and should probably be refactored
        Ok(encapsulation_key
            .encrypt(&mut context, SymmetricKeyId::Local("wrapping_key"))?
            .to_string())
    }

    pub fn unwrap_encapsulation_key(
        wrapped_key: String,
        wrapping_key: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let tmp_store: KeyStore<KeyIds> = KeyStore::default();
        let mut context = tmp_store.context();
        #[allow(deprecated)]
        context.set_symmetric_key(
            SymmetricKeyId::Local("wrapping_key"),
            SymmetricCryptoKey::try_from(wrapping_key)?,
        )?;
        // Note: The order of arguments is different here, and should probably be refactored
        EncString::from_str(wrapped_key.as_str())?
            .decrypt(&mut context, SymmetricKeyId::Local("wrapping_key"))
    }

    pub fn wrap_decapsulation_key(
        decapsulation_key: Vec<u8>,
        wrapping_key: Vec<u8>,
    ) -> Result<String, CryptoError> {
        let tmp_store: KeyStore<KeyIds> = KeyStore::default();
        let mut context = tmp_store.context();
        #[allow(deprecated)]
        context.set_symmetric_key(
            SymmetricKeyId::Local("wrapping_key"),
            SymmetricCryptoKey::try_from(wrapping_key)?,
        )?;
        // Note: The order of arguments is different here, and should probably be refactored
        Ok(decapsulation_key
            .encrypt(&mut context, SymmetricKeyId::Local("wrapping_key"))?
            .to_string())
    }

    pub fn unwrap_decapsulation_key(
        wrapped_key: String,
        wrapping_key: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let tmp_store: KeyStore<KeyIds> = KeyStore::default();
        let mut context = tmp_store.context();
        #[allow(deprecated)]
        context.set_symmetric_key(
            SymmetricKeyId::Local("wrapping_key"),
            SymmetricCryptoKey::try_from(wrapping_key)?,
        )?;
        // Note: The order of arguments is different here, and should probably be refactored
        EncString::from_str(wrapped_key.as_str())?
            .decrypt(&mut context, SymmetricKeyId::Local("wrapping_key"))
    }

    // Key encapsulation
    pub fn encapsulate_key_unsigned(
        shared_key: Vec<u8>,
        encapsulation_key: Vec<u8>,
    ) -> Result<String, CryptoError> {
        let encapsulation_key = AsymmetricPublicCryptoKey::from_der(encapsulation_key.as_slice())?;
        Ok(UnsignedSharedKey::encapsulate_key_unsigned(
            &SymmetricCryptoKey::try_from(shared_key)?,
            &encapsulation_key,
        )?
        .to_string())
    }

    pub fn decapsulate_key_unsigned(
        encapsulated_key: String,
        decapsulation_key: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        Ok(UnsignedSharedKey::from_str(encapsulated_key.as_str())?
            .decapsulate_key_unsigned(&AsymmetricCryptoKey::from_der(
                decapsulation_key.as_slice(),
            )?)?
            .to_encoded())
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

    const PEM_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQDiTQVuzhdygFz5
qv14i+XFDGTnDravzUQT1hPKPGUZOUSZ1gwdNgkWqOIaOnR65BHEnL0sp4bnuiYc
afeK2JAW5Sc8Z7IxBNSuAwhQmuKx3RochMIiuCkI2/p+JvUQoJu6FBNm8OoJ4Cwm
qqHGZESMfnpQDCuDrB3JdJEdXhtmnl0C48sGjOk3WaBMcgGqn8LbJDUlyu1zdqyv
b0waJf0iV4PJm2fkUl7+57D/2TkpbCqURVnZK1FFIEg8mr6FzSN1F2pOfktkNYZw
P7MSNR7o81CkRSCMr7EkIVa+MZYMBx106BMK7FXgWB7nbSpsWKxBk7ZDHkID2fam
rEcVtrzDAgMBAAECggEBAKwq9OssGGKgjhvUnyrLJHAZ0dqIMyzk+dotkLjX4gKi
szJmyqiep6N5sStLNbsZMPtoU/RZMCW0VbJgXFhiEp2YkZU/Py5UAoqw++53J+kx
0d/IkPphKbb3xUec0+1mg5O6GljDCQuiZXS1dIa/WfeZcezclW6Dz9WovY6ePjJ+
8vEBR1icbNKzyeINd6MtPtpcgQPHtDwHvhPyUDbKDYGbLvjh9nui8h4+ZUlXKuVR
jB0ChxiKV1xJRjkrEVoulOOicd5r597WfB2ghax3pvRZ4MdXemCXm3gQYqPVKach
vGU+1cPQR/MBJZpxT+EZA97xwtFS3gqwbxJaNFcoE8ECgYEA9OaeYZhQPDo485tI
1u/Z7L/3PNape9hBQIXoW7+MgcQ5NiWqYh8Jnj43EIYa0wM/ECQINr1Za8Q5e6KR
J30FcU+kfyjuQ0jeXdNELGU/fx5XXNg/vV8GevHwxRlwzqZTCg6UExUZzbYEQqd7
l+wPyETGeua5xCEywA1nX/D101kCgYEA7I6aMFjhEjO71RmzNhqjKJt6DOghoOfQ
TjhaaanNEhLYSbenFz1mlb21mW67ulmz162saKdIYLxQNJIP8ZPmxh4ummOJI8w9
ClHfo8WuCI2hCjJ19xbQJocSbTA5aJg6lA1IDVZMDbQwsnAByPRGpaLHBT/Q9Bye
KvCMB+9amXsCgYEAx65yXSkP4sumPBrVHUub6MntERIGRxBgw/drKcPZEMWp0FiN
wEuGUBxyUWrG3F69QK/gcqGZE6F/LSu0JvptQaKqgXQiMYJsrRvhbkFvsHpQyUcZ
UZL1ebFjm5HOxPAgrQaN/bEqxOwwNRjSUWEMzUImg3c06JIZCzbinvudtKECgYEA
kY3JF/iIPI/yglP27lKDlCfeeHSYxI3+oTKRhzSAxx8rUGidenJAXeDGDauR/T7W
pt3pGNfddBBK9Z3uC4Iq3DqUCFE4f/taj7ADAJ1Q0Vh7/28/IJM77ojr8J1cpZwN
Zy2o6PPxhfkagaDjqEeN9Lrs5LD4nEvDkr5CG1vOjmMCgYEAvIBFKRm31NyF8jLi
CVuPwC5PzrW5iThDmsWTaXFpB3esUsbICO2pEz872oeQS+Em4GO5vXUlpbbFPzup
PFhA8iMJ8TAvemhvc7oM0OZqpU6p3K4seHf6BkwLxumoA3vDJfovu9RuXVcJVOnf
DnqOsltgPomWZ7xVfMkm9niL2OA=
-----END PRIVATE KEY-----";

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

    #[test]
    fn test_wrap_unwrap_symmetric_key() {
        let key_to_be_wrapped = PureCrypto::generate_user_key_aes256_cbc_hmac();
        let wrapping_key = PureCrypto::generate_user_key_aes256_cbc_hmac();
        let wrapped_key =
            PureCrypto::wrap_symmetric_key(key_to_be_wrapped.clone(), wrapping_key.clone())
                .unwrap();
        let unwrapped_key = PureCrypto::unwrap_symmetric_key(wrapped_key, wrapping_key).unwrap();
        assert_eq!(key_to_be_wrapped, unwrapped_key);
    }

    #[test]
    fn test_wrap_encapsulation_key() {
        let decapsulation_key = AsymmetricCryptoKey::from_pem(PEM_KEY).unwrap();
        let encapsulation_key = decapsulation_key.to_public_der().unwrap();
        let wrapping_key = PureCrypto::generate_user_key_aes256_cbc_hmac();
        let wrapped_key =
            PureCrypto::wrap_encapsulation_key(encapsulation_key.clone(), wrapping_key.clone())
                .unwrap();
        let unwrapped_key =
            PureCrypto::unwrap_encapsulation_key(wrapped_key, wrapping_key).unwrap();
        assert_eq!(encapsulation_key, unwrapped_key);
    }

    #[test]
    fn test_wrap_decapsulation_key() {
        let decapsulation_key = AsymmetricCryptoKey::from_pem(PEM_KEY).unwrap();
        let wrapping_key = PureCrypto::generate_user_key_aes256_cbc_hmac();
        let wrapped_key = PureCrypto::wrap_decapsulation_key(
            decapsulation_key.to_der().unwrap(),
            wrapping_key.clone(),
        )
        .unwrap();
        let unwrapped_key =
            PureCrypto::unwrap_decapsulation_key(wrapped_key, wrapping_key).unwrap();
        assert_eq!(decapsulation_key.to_der().unwrap(), unwrapped_key);
    }

    #[test]
    fn test_encapsulate_key_unsigned() {
        let shared_key = PureCrypto::generate_user_key_aes256_cbc_hmac();
        let decapsulation_key = AsymmetricCryptoKey::from_pem(PEM_KEY).unwrap();
        let encapsulation_key = decapsulation_key.to_public_der().unwrap();
        let encapsulated_key =
            PureCrypto::encapsulate_key_unsigned(shared_key.clone(), encapsulation_key.clone())
                .unwrap();
        let unwrapped_key = PureCrypto::decapsulate_key_unsigned(
            encapsulated_key,
            decapsulation_key.to_der().unwrap(),
        )
        .unwrap();
        assert_eq!(shared_key, unwrapped_key);
    }
}

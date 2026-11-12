use std::str::FromStr;

use bitwarden_core::key_management::KeySlotIds;
#[allow(deprecated)]
use bitwarden_crypto::dangerous_derive_kdf_material;
use bitwarden_crypto::{
    BitwardenLegacyKeyBytes, CryptoError, Decryptable, EncString, Kdf, KeyDecryptable,
    KeyEncryptable, KeyStore, MasterKey, OctetStreamBytes, Pkcs8PrivateKeyBytes,
    PrimitiveEncryptable, PrivateKey, PublicKey, PublicKeyEncryptionAlgorithm, SpkiPublicKeyBytes,
    SymmetricCryptoKey, SymmetricKeyAlgorithm, UnsignedSharedKey,
};
use rand::RngExt;
use rsa::{
    Oaep, RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
};
use sha1::Sha1;

/// This module represents a stopgap solution to provide access to primitive crypto functions for JS
/// clients. It is not intended to be used outside of the JS clients and this pattern should not be
/// proliferated. It is necessary because we want to use SDK crypto prior to the SDK being fully
/// responsible for state and keys.
#[bitwarden_ffi::wasm_object]
pub struct PureCrypto {}

// Encryption
#[bitwarden_ffi::wasm_export]
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
        let _span = tracing::info_span!("PureCrypto::symmetric_decrypt_string").entered();
        let key = &BitwardenLegacyKeyBytes::from(key);
        EncString::from_str(&enc_string)?.decrypt_with_key(&SymmetricCryptoKey::try_from(key)?)
    }

    pub fn symmetric_decrypt_bytes(
        enc_string: String,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let _span = tracing::info_span!("PureCrypto::symmetric_decrypt_bytes").entered();
        let key = &BitwardenLegacyKeyBytes::from(key);
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
        let _span = tracing::info_span!("PureCrypto::symmetric_decrypt_filedata").entered();
        let key = &BitwardenLegacyKeyBytes::from(key);
        EncString::from_buffer(&enc_bytes)?.decrypt_with_key(&SymmetricCryptoKey::try_from(key)?)
    }

    pub fn symmetric_encrypt_string(plain: String, key: Vec<u8>) -> Result<String, CryptoError> {
        let _span = tracing::info_span!("PureCrypto::symmetric_encrypt_string").entered();
        let key = &BitwardenLegacyKeyBytes::from(key);
        plain
            .encrypt_with_key(&SymmetricCryptoKey::try_from(key)?)
            .map(|enc| enc.to_string())
    }

    /// DEPRECATED: Only used by send keys
    pub fn symmetric_encrypt_bytes(plain: Vec<u8>, key: Vec<u8>) -> Result<String, CryptoError> {
        let _span = tracing::info_span!("PureCrypto::symmetric_encrypt_bytes").entered();
        let key = &BitwardenLegacyKeyBytes::from(key);
        OctetStreamBytes::from(plain)
            .encrypt_with_key(&SymmetricCryptoKey::try_from(key)?)
            .map(|enc| enc.to_string())
    }

    pub fn symmetric_encrypt_filedata(
        plain: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let _span = tracing::info_span!("PureCrypto::symmetric_encrypt_filedata").entered();
        let key = &BitwardenLegacyKeyBytes::from(key);
        OctetStreamBytes::from(plain)
            .encrypt_with_key(&SymmetricCryptoKey::try_from(key)?)?
            .to_buffer()
    }

    pub fn decrypt_user_key_with_master_password(
        encrypted_user_key: String,
        master_password: String,
        email: String,
        kdf: Kdf,
    ) -> Result<Vec<u8>, CryptoError> {
        let _span = tracing::info_span!(
            "PureCrypto::decrypt_user_key_with_master_password",
            email = %email,
            kdf = ?kdf
        )
        .entered();

        let master_key = MasterKey::derive(master_password.as_str(), email.as_str(), &kdf)?;
        let encrypted_user_key = EncString::from_str(&encrypted_user_key)?;
        let result = master_key
            .decrypt_user_key(encrypted_user_key)
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(result.to_encoded().to_vec())
    }

    pub fn encrypt_user_key_with_master_password(
        user_key: Vec<u8>,
        master_password: String,
        email: String,
        kdf: Kdf,
    ) -> Result<String, CryptoError> {
        let _span = tracing::info_span!(
            "PureCrypto::encrypt_user_key_with_master_password",
            email = %email,
            kdf = ?kdf
        )
        .entered();
        let master_key = MasterKey::derive(master_password.as_str(), email.as_str(), &kdf)?;
        let user_key = &BitwardenLegacyKeyBytes::from(user_key);
        let user_key = SymmetricCryptoKey::try_from(user_key)?;
        let result = master_key.encrypt_user_key(&user_key)?;
        Ok(result.to_string())
    }

    pub fn make_user_key_aes256_cbc_hmac() -> Vec<u8> {
        SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac)
            .to_encoded()
            .to_vec()
    }

    #[wasm_bindgen(unchecked_return_type = "SymmetricKey")]
    pub fn make_aes256_cbc_hmac_key() -> SymmetricCryptoKey {
        SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac)
    }

    /// Wraps (encrypts) a symmetric key using a symmetric wrapping key, returning the wrapped key
    /// as an EncString.
    pub fn wrap_symmetric_key(
        key_to_be_wrapped: Vec<u8>,
        wrapping_key: Vec<u8>,
    ) -> Result<String, CryptoError> {
        let _span = tracing::info_span!("PureCrypto::wrap_symmetric_key").entered();
        let tmp_store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut context = tmp_store.context();
        let wrapping_key =
            SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(wrapping_key))?;
        let wrapping_key = context.add_local_symmetric_key(wrapping_key);
        let key_to_be_wrapped =
            SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(key_to_be_wrapped))?;
        let key_to_wrap = context.add_local_symmetric_key(key_to_be_wrapped);
        // Note: The order of arguments is different here, and should probably be refactored
        Ok(context
            .wrap_symmetric_key(wrapping_key, key_to_wrap)?
            .to_string())
    }

    /// Unwraps (decrypts) a wrapped symmetric key using a symmetric wrapping key, returning the
    /// unwrapped key as a serialized byte array.
    pub fn unwrap_symmetric_key(
        wrapped_key: String,
        wrapping_key: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let _span = tracing::info_span!("PureCrypto::unwrap_symmetric_key").entered();
        let tmp_store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut context = tmp_store.context();
        let wrapping_key =
            SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(wrapping_key))?;
        let wrapping_key = context.add_local_symmetric_key(wrapping_key);
        // Note: The order of arguments is different here, and should probably be refactored
        let unwrapped = context
            .unwrap_symmetric_key(wrapping_key, &EncString::from_str(wrapped_key.as_str())?)?;
        #[allow(deprecated)]
        let key = context.dangerous_get_symmetric_key(unwrapped)?;
        Ok(key.to_encoded().to_vec())
    }

    /// Wraps (encrypts) an SPKI DER encoded encapsulation (public) key using a symmetric wrapping
    /// key. Note: Usually, a public key is - by definition - public, so this should not be
    /// used. The specific use-case for this function is to enable rotateable key sets, where
    /// the "public key" is not public, with the intent of preventing the server from being able
    /// to overwrite the user key unlocked by the rotateable keyset.
    pub fn wrap_encapsulation_key(
        encapsulation_key: Vec<u8>,
        wrapping_key: Vec<u8>,
    ) -> Result<String, CryptoError> {
        let _span = tracing::info_span!("PureCrypto::wrap_encapsulation_key").entered();
        let tmp_store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut context = tmp_store.context();
        let wrapping_key = context.add_local_symmetric_key(SymmetricCryptoKey::try_from(
            &BitwardenLegacyKeyBytes::from(wrapping_key),
        )?);
        Ok(SpkiPublicKeyBytes::from(encapsulation_key)
            .encrypt(&mut context, wrapping_key)?
            .to_string())
    }

    /// Unwraps (decrypts) a wrapped SPKI DER encoded encapsulation (public) key using a symmetric
    /// wrapping key.
    pub fn unwrap_encapsulation_key(
        wrapped_key: String,
        wrapping_key: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let _span = tracing::info_span!("PureCrypto::unwrap_encapsulation_key").entered();
        let tmp_store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut context = tmp_store.context();
        let wrapping_key = context.add_local_symmetric_key(SymmetricCryptoKey::try_from(
            &BitwardenLegacyKeyBytes::from(wrapping_key),
        )?);
        EncString::from_str(wrapped_key.as_str())?.decrypt(&mut context, wrapping_key)
    }

    /// Wraps (encrypts) a PKCS8 DER encoded decapsulation (private) key using a symmetric wrapping
    /// key,
    pub fn wrap_decapsulation_key(
        decapsulation_key: Vec<u8>,
        wrapping_key: Vec<u8>,
    ) -> Result<String, CryptoError> {
        let _span = tracing::info_span!("PureCrypto::wrap_decapsulation_key").entered();
        let tmp_store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut context = tmp_store.context();
        let wrapping_key = context.add_local_symmetric_key(SymmetricCryptoKey::try_from(
            &BitwardenLegacyKeyBytes::from(wrapping_key),
        )?);
        Ok(Pkcs8PrivateKeyBytes::from(decapsulation_key)
            .encrypt(&mut context, wrapping_key)?
            .to_string())
    }

    /// Unwraps (decrypts) a wrapped PKCS8 DER encoded decapsulation (private) key using a symmetric
    /// wrapping key.
    pub fn unwrap_decapsulation_key(
        wrapped_key: String,
        wrapping_key: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let _span = tracing::info_span!("PureCrypto::unwrap_decapsulation_key").entered();
        let tmp_store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut context = tmp_store.context();
        let wrapping_key = context.add_local_symmetric_key(SymmetricCryptoKey::try_from(
            &BitwardenLegacyKeyBytes::from(wrapping_key),
        )?);
        EncString::from_str(wrapped_key.as_str())?.decrypt(&mut context, wrapping_key)
    }

    /// Encapsulates (encrypts) a symmetric key using an public-key/encapsulation-key
    /// in SPKI format, returning the encapsulated key as a string. Note: This is unsigned, so
    /// the sender's authenticity cannot be verified by the recipient.
    pub fn encapsulate_key_unsigned(
        shared_key: Vec<u8>,
        encapsulation_key: Vec<u8>,
    ) -> Result<String, CryptoError> {
        let _span = tracing::info_span!("PureCrypto::encapsulate_key_unsigned").entered();
        let encapsulation_key = PublicKey::from_der(&SpkiPublicKeyBytes::from(encapsulation_key))?;
        #[expect(deprecated)]
        Ok(UnsignedSharedKey::encapsulate_key_unsigned(
            &SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(shared_key))?,
            &encapsulation_key,
        )?
        .to_string())
    }

    /// Decapsulates (decrypts) a symmetric key using an decapsulation-key/private-key in PKCS8
    /// DER format. Note: This is unsigned, so the sender's authenticity cannot be verified by the
    /// recipient.
    pub fn decapsulate_key_unsigned(
        encapsulated_key: String,
        decapsulation_key: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let _span = tracing::info_span!("PureCrypto::decapsulate_key_unsigned").entered();
        #[expect(deprecated)]
        Ok(UnsignedSharedKey::from_str(encapsulated_key.as_str())?
            .decapsulate_key_unsigned(&PrivateKey::from_der(&Pkcs8PrivateKeyBytes::from(
                decapsulation_key,
            ))?)?
            .to_encoded()
            .to_vec())
    }

    /// Derive output of the KDF for a [bitwarden_crypto::Kdf] configuration.
    pub fn derive_kdf_material(
        password: &[u8],
        salt: &[u8],
        kdf: Kdf,
    ) -> Result<Vec<u8>, CryptoError> {
        let _span = tracing::info_span!("PureCrypto::derive_kdf_material", kdf = ?kdf).entered();
        #[allow(deprecated)]
        dangerous_derive_kdf_material(password, salt, &kdf)
    }

    /// Given a decrypted private RSA key PKCS8 DER this
    /// returns the corresponding public RSA key in DER format.
    /// HAZMAT WARNING: Do not use outside of implementing cryptofunctionservice
    pub fn rsa_extract_public_key(private_key: Vec<u8>) -> Result<Vec<u8>, RsaError> {
        let _span = tracing::info_span!("PureCrypto::rsa_extract_public_key").entered();
        let private_key = PrivateKey::from_der(&Pkcs8PrivateKeyBytes::from(private_key))
            .map_err(|_| RsaError::KeyParse)?;
        let public_key = private_key.to_public_key();
        Ok(public_key
            .to_der()
            .map_err(|_| RsaError::KeySerialize)?
            .to_vec())
    }

    /// Generates a new RSA key pair and returns the private key
    /// HAZMAT WARNING: Do not use outside of implementing cryptofunctionservice
    pub fn rsa_generate_keypair() -> Result<Vec<u8>, RsaError> {
        let _span = tracing::info_span!("PureCrypto::rsa_generate_keypair").entered();
        let private_key = PrivateKey::make(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        Ok(private_key
            .to_der()
            .map_err(|_| RsaError::KeySerialize)?
            .to_vec())
    }

    /// Decrypts data using RSAES-OAEP with SHA-1
    /// HAZMAT WARNING: Do not use outside of implementing cryptofunctionservice
    pub fn rsa_decrypt_data(
        encrypted_data: Vec<u8>,
        private_key: Vec<u8>,
    ) -> Result<Vec<u8>, RsaError> {
        let _span = tracing::info_span!("PureCrypto::rsa_decrypt_data").entered();
        let private_key = RsaPrivateKey::from_pkcs8_der(private_key.as_slice())
            .map_err(|_| RsaError::KeyParse)?;
        let padding = Oaep::<Sha1>::new();
        private_key
            .decrypt(padding, &encrypted_data)
            .map_err(|_| RsaError::Decryption)
    }

    /// Encrypts data using RSAES-OAEP with SHA-1
    /// HAZMAT WARNING: Do not use outside of implementing cryptofunctionservice
    pub fn rsa_encrypt_data(plain_data: Vec<u8>, public_key: Vec<u8>) -> Result<Vec<u8>, RsaError> {
        let _span = tracing::info_span!("PureCrypto::rsa_encrypt_data").entered();
        let public_key = RsaPublicKey::from_public_key_der(public_key.as_slice())
            .map_err(|_| RsaError::KeyParse)?;
        let padding = Oaep::<Sha1>::new();
        let mut rng = bitwarden_random::rng();
        public_key
            .encrypt(&mut rng, padding, &plain_data)
            .map_err(|_| RsaError::Encryption)
    }

    /// Generates a cryptographically secure random number between the given min and max
    /// (inclusive).
    #[deprecated(
        note = "Use `SdkRandomNumberClient::gen_range` instead. This method will be removed in a future release."
    )]
    #[allow(deprecated, reason = "wasm_bindgen glue calls this deprecated method")]
    pub fn random_number(min: u32, max: u32) -> u32 {
        let _span = tracing::info_span!("PureCrypto::random_number").entered();
        let mut rng = bitwarden_random::rng();
        rng.random_range(min..=max)
    }

    /// Generates a new v4 UUID using a cryptographically secure random number generator
    #[deprecated(
        note = "Use `SdkRandomNumberClient::gen_uuid` instead. This method will be removed in a future release."
    )]
    #[allow(deprecated, reason = "wasm_bindgen glue calls this deprecated method")]
    pub fn new_guid() -> String {
        let _span = tracing::info_span!("PureCrypto::new_guid").entered();
        uuid::Uuid::new_v4().to_string()
    }
}

#[bitwarden_ffi::wasm_object]
#[derive(Debug)]
pub enum RsaError {
    Decryption,
    Encryption,
    KeyParse,
    KeySerialize,
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

    const DERIVED_KDF_MATERIAL_PBKDF2: &[u8] = &[
        129, 57, 137, 140, 156, 220, 110, 212, 201, 255, 52, 182, 22, 206, 221, 66, 136, 199, 181,
        89, 252, 175, 82, 168, 79, 204, 88, 174, 166, 60, 52, 79,
    ];
    const DERIVED_KDF_MATERIAL_ARGON2ID: &[u8] = &[
        221, 57, 158, 206, 27, 154, 188, 170, 33, 198, 250, 144, 191, 231, 29, 74, 201, 102, 253,
        77, 8, 128, 173, 111, 217, 41, 125, 9, 156, 52, 112, 140,
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
        let key = PureCrypto::make_user_key_aes256_cbc_hmac();
        assert_eq!(key.len(), 64);
    }

    #[test]
    fn roundtrip_encrypt_user_key_with_master_password() {
        let master_password = "test";
        let email = "test@example.com";
        let kdf = Kdf::PBKDF2 {
            iterations: NonZero::try_from(600000).unwrap(),
        };
        let user_key = PureCrypto::make_user_key_aes256_cbc_hmac();
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
        let key_to_be_wrapped = PureCrypto::make_user_key_aes256_cbc_hmac();
        let wrapping_key = PureCrypto::make_user_key_aes256_cbc_hmac();
        let wrapped_key =
            PureCrypto::wrap_symmetric_key(key_to_be_wrapped.clone(), wrapping_key.clone())
                .unwrap();
        let unwrapped_key = PureCrypto::unwrap_symmetric_key(wrapped_key, wrapping_key).unwrap();
        assert_eq!(key_to_be_wrapped, unwrapped_key);
    }

    #[test]
    fn test_wrap_encapsulation_key() {
        let decapsulation_key = PrivateKey::from_pem(PEM_KEY).unwrap();
        let encapsulation_key = decapsulation_key
            .to_public_key()
            .to_der()
            .unwrap()
            .as_ref()
            .to_vec();
        let wrapping_key = PureCrypto::make_user_key_aes256_cbc_hmac();
        let wrapped_key =
            PureCrypto::wrap_encapsulation_key(encapsulation_key.clone(), wrapping_key.clone())
                .unwrap();
        let unwrapped_key =
            PureCrypto::unwrap_encapsulation_key(wrapped_key, wrapping_key).unwrap();
        assert_eq!(encapsulation_key, unwrapped_key);
    }

    #[test]
    fn test_wrap_decapsulation_key() {
        let decapsulation_key = PrivateKey::from_pem(PEM_KEY).unwrap();
        let wrapping_key = PureCrypto::make_user_key_aes256_cbc_hmac();
        let wrapped_key = PureCrypto::wrap_decapsulation_key(
            decapsulation_key.to_der().unwrap().to_vec(),
            wrapping_key.clone(),
        )
        .unwrap();
        let unwrapped_key =
            PureCrypto::unwrap_decapsulation_key(wrapped_key, wrapping_key).unwrap();
        assert_eq!(decapsulation_key.to_der().unwrap().to_vec(), unwrapped_key);
    }

    #[test]
    fn test_encapsulate_key_unsigned() {
        let shared_key = PureCrypto::make_user_key_aes256_cbc_hmac();
        let decapsulation_key = PrivateKey::from_pem(PEM_KEY).unwrap();
        let encapsulation_key = decapsulation_key.to_public_key().to_der().unwrap();
        let encapsulated_key = PureCrypto::encapsulate_key_unsigned(
            shared_key.clone(),
            encapsulation_key.clone().to_vec(),
        )
        .unwrap();
        let unwrapped_key = PureCrypto::decapsulate_key_unsigned(
            encapsulated_key,
            decapsulation_key.to_der().unwrap().to_vec(),
        )
        .unwrap();
        assert_eq!(shared_key, unwrapped_key);
    }

    #[test]
    fn test_derive_pbkdf2_output() {
        let password = "test_password".as_bytes();
        let email = "test_email@example.com".as_bytes();
        let kdf = Kdf::PBKDF2 {
            iterations: NonZero::try_from(600000).unwrap(),
        };
        let derived_key = PureCrypto::derive_kdf_material(password, email, kdf).unwrap();
        assert_eq!(derived_key, DERIVED_KDF_MATERIAL_PBKDF2);
    }

    #[test]
    fn test_derived_argon2_output() {
        let password = "test_password".as_bytes();
        let email = "test_email@example.com".as_bytes();
        let kdf = Kdf::Argon2id {
            iterations: NonZero::try_from(3).unwrap(),
            memory: NonZero::try_from(64).unwrap(),
            parallelism: NonZero::try_from(4).unwrap(),
        };
        let derived_key = PureCrypto::derive_kdf_material(password, email, kdf).unwrap();
        assert_eq!(derived_key, DERIVED_KDF_MATERIAL_ARGON2ID);
    }

    #[test]
    fn test_rsa_round_trip() {
        let private_key = PureCrypto::rsa_generate_keypair().unwrap();
        let public_key = PureCrypto::rsa_extract_public_key(private_key.clone()).unwrap();
        let plain_data = b"Test RSA encryption data".to_vec();
        let encrypted_data = PureCrypto::rsa_encrypt_data(plain_data.clone(), public_key).unwrap();
        let decrypted_data = PureCrypto::rsa_decrypt_data(encrypted_data, private_key).unwrap();
        assert_eq!(plain_data, decrypted_data);
    }

    #[test]
    #[expect(
        deprecated,
        reason = "Exercises the deprecated new_guid until it is removed"
    )]
    fn test_new_guid_is_v4_and_unique() {
        let first = PureCrypto::new_guid();
        let second = PureCrypto::new_guid();

        let parsed = uuid::Uuid::parse_str(&first).expect("new_guid output must parse as a UUID");
        assert_eq!(parsed.get_version_num(), 4);
        assert_ne!(first, second);
    }
}

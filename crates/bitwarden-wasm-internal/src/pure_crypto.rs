use std::str::FromStr;

use bitwarden_core::key_management::{KeyIds, SymmetricKeyId};
use bitwarden_crypto::{
    AsymmetricCryptoKey, AsymmetricPublicCryptoKey, BitwardenLegacyKeyBytes, CoseKeyBytes,
    CoseSerializable, CoseSign1Bytes, CryptoError, Decryptable, EncString, Kdf, KeyDecryptable,
    KeyEncryptable, KeyStore, MasterKey, OctetStreamBytes, Pkcs8PrivateKeyBytes,
    PrimitiveEncryptable, SignatureAlgorithm, SignedPublicKey, SigningKey, SpkiPublicKeyBytes,
    SymmetricCryptoKey, UnsignedSharedKey, VerifyingKey,
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
        let key = &BitwardenLegacyKeyBytes::from(key);
        EncString::from_str(&enc_string)?.decrypt_with_key(&SymmetricCryptoKey::try_from(key)?)
    }

    pub fn symmetric_decrypt_bytes(
        enc_string: String,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
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
        let key = &BitwardenLegacyKeyBytes::from(key);
        EncString::from_buffer(&enc_bytes)?.decrypt_with_key(&SymmetricCryptoKey::try_from(key)?)
    }

    pub fn symmetric_encrypt_string(plain: String, key: Vec<u8>) -> Result<String, CryptoError> {
        let key = &BitwardenLegacyKeyBytes::from(key);
        plain
            .encrypt_with_key(&SymmetricCryptoKey::try_from(key)?)
            .map(|enc| enc.to_string())
    }

    /// DEPRECATED: Only used by send keys
    pub fn symmetric_encrypt_bytes(plain: Vec<u8>, key: Vec<u8>) -> Result<String, CryptoError> {
        let key = &BitwardenLegacyKeyBytes::from(key);
        OctetStreamBytes::from(plain)
            .encrypt_with_key(&SymmetricCryptoKey::try_from(key)?)
            .map(|enc| enc.to_string())
    }

    pub fn symmetric_encrypt_filedata(
        plain: Vec<u8>,
        key: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
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
        let master_key = MasterKey::derive(master_password.as_str(), email.as_str(), &kdf)?;
        let user_key = &BitwardenLegacyKeyBytes::from(user_key);
        let user_key = SymmetricCryptoKey::try_from(user_key)?;
        let result = master_key.encrypt_user_key(&user_key)?;
        Ok(result.to_string())
    }

    pub fn make_user_key_aes256_cbc_hmac() -> Vec<u8> {
        SymmetricCryptoKey::make_aes256_cbc_hmac_key()
            .to_encoded()
            .to_vec()
    }

    pub fn make_user_key_xchacha20_poly1305() -> Vec<u8> {
        SymmetricCryptoKey::make_xchacha20_poly1305_key()
            .to_encoded()
            .to_vec()
    }

    /// Wraps (encrypts) a symmetric key using a symmetric wrapping key, returning the wrapped key
    /// as an EncString.
    pub fn wrap_symmetric_key(
        key_to_be_wrapped: Vec<u8>,
        wrapping_key: Vec<u8>,
    ) -> Result<String, CryptoError> {
        let tmp_store: KeyStore<KeyIds> = KeyStore::default();
        let mut context = tmp_store.context();
        let wrapping_key =
            SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(wrapping_key))?;
        #[allow(deprecated)]
        context.set_symmetric_key(SymmetricKeyId::Local("wrapping_key"), wrapping_key)?;
        let key_to_be_wrapped =
            SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(key_to_be_wrapped))?;
        #[allow(deprecated)]
        context.set_symmetric_key(SymmetricKeyId::Local("key_to_wrap"), key_to_be_wrapped)?;
        // Note: The order of arguments is different here, and should probably be refactored
        Ok(context
            .wrap_symmetric_key(
                SymmetricKeyId::Local("wrapping_key"),
                SymmetricKeyId::Local("key_to_wrap"),
            )?
            .to_string())
    }

    /// Unwraps (decrypts) a wrapped symmetric key using a symmetric wrapping key, returning the
    /// unwrapped key as a serialized byte array.
    pub fn unwrap_symmetric_key(
        wrapped_key: String,
        wrapping_key: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let tmp_store: KeyStore<KeyIds> = KeyStore::default();
        let mut context = tmp_store.context();
        let wrapping_key =
            SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(wrapping_key))?;
        #[allow(deprecated)]
        context.set_symmetric_key(SymmetricKeyId::Local("wrapping_key"), wrapping_key)?;
        // Note: The order of arguments is different here, and should probably be refactored
        context.unwrap_symmetric_key(
            SymmetricKeyId::Local("wrapping_key"),
            SymmetricKeyId::Local("wrapped_key"),
            &EncString::from_str(wrapped_key.as_str())?,
        )?;
        #[allow(deprecated)]
        let key = context.dangerous_get_symmetric_key(SymmetricKeyId::Local("wrapped_key"))?;
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
        let tmp_store: KeyStore<KeyIds> = KeyStore::default();
        let mut context = tmp_store.context();
        #[allow(deprecated)]
        context.set_symmetric_key(
            SymmetricKeyId::Local("wrapping_key"),
            SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(wrapping_key))?,
        )?;
        Ok(SpkiPublicKeyBytes::from(encapsulation_key)
            .encrypt(&mut context, SymmetricKeyId::Local("wrapping_key"))?
            .to_string())
    }

    /// Unwraps (decrypts) a wrapped SPKI DER encoded encapsulation (public) key using a symmetric
    /// wrapping key.
    pub fn unwrap_encapsulation_key(
        wrapped_key: String,
        wrapping_key: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let tmp_store: KeyStore<KeyIds> = KeyStore::default();
        let mut context = tmp_store.context();
        #[allow(deprecated)]
        context.set_symmetric_key(
            SymmetricKeyId::Local("wrapping_key"),
            SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(wrapping_key))?,
        )?;
        EncString::from_str(wrapped_key.as_str())?
            .decrypt(&mut context, SymmetricKeyId::Local("wrapping_key"))
    }

    /// Wraps (encrypts) a PKCS8 DER encoded decapsulation (private) key using a symmetric wrapping
    /// key,
    pub fn wrap_decapsulation_key(
        decapsulation_key: Vec<u8>,
        wrapping_key: Vec<u8>,
    ) -> Result<String, CryptoError> {
        let tmp_store: KeyStore<KeyIds> = KeyStore::default();
        let mut context = tmp_store.context();
        #[allow(deprecated)]
        context.set_symmetric_key(
            SymmetricKeyId::Local("wrapping_key"),
            SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(wrapping_key))?,
        )?;
        Ok(Pkcs8PrivateKeyBytes::from(decapsulation_key)
            .encrypt(&mut context, SymmetricKeyId::Local("wrapping_key"))?
            .to_string())
    }

    /// Unwraps (decrypts) a wrapped PKCS8 DER encoded decapsulation (private) key using a symmetric
    /// wrapping key.
    pub fn unwrap_decapsulation_key(
        wrapped_key: String,
        wrapping_key: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let tmp_store: KeyStore<KeyIds> = KeyStore::default();
        let mut context = tmp_store.context();
        #[allow(deprecated)]
        context.set_symmetric_key(
            SymmetricKeyId::Local("wrapping_key"),
            SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(wrapping_key))?,
        )?;
        EncString::from_str(wrapped_key.as_str())?
            .decrypt(&mut context, SymmetricKeyId::Local("wrapping_key"))
    }

    /// Encapsulates (encrypts) a symmetric key using an asymmetric encapsulation key (public key)
    /// in SPKI format, returning the encapsulated key as a string. Note: This is unsigned, so
    /// the sender's authenticity cannot be verified by the recipient.
    pub fn encapsulate_key_unsigned(
        shared_key: Vec<u8>,
        encapsulation_key: Vec<u8>,
    ) -> Result<String, CryptoError> {
        let encapsulation_key = AsymmetricPublicCryptoKey::from_der(&SpkiPublicKeyBytes::from(
            encapsulation_key.as_slice(),
        ))?;
        Ok(UnsignedSharedKey::encapsulate_key_unsigned(
            &SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(shared_key))?,
            &encapsulation_key,
        )?
        .to_string())
    }

    /// Decapsulates (decrypts) a symmetric key using an decapsulation key (private key) in PKCS8
    /// DER format. Note: This is unsigned, so the sender's authenticity cannot be verified by the
    /// recipient.
    pub fn decapsulate_key_unsigned(
        encapsulated_key: String,
        decapsulation_key: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        Ok(UnsignedSharedKey::from_str(encapsulated_key.as_str())?
            .decapsulate_key_unsigned(&AsymmetricCryptoKey::from_der(
                &Pkcs8PrivateKeyBytes::from(decapsulation_key),
            )?)?
            .to_encoded()
            .to_vec())
    }

    /// Given a wrapped signing key and the symmetric key it is wrapped with, this returns
    /// the corresponding verifying key.
    pub fn verifying_key_for_signing_key(
        signing_key: String,
        wrapping_key: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let bytes = Self::symmetric_decrypt_bytes(signing_key, wrapping_key)?;
        let signing_key = SigningKey::from_cose(&CoseKeyBytes::from(bytes))?;
        let verifying_key = signing_key.to_verifying_key();
        Ok(verifying_key.to_cose().to_vec())
    }

    /// Returns the algorithm used for the given verifying key.
    pub fn key_algorithm_for_verifying_key(
        verifying_key: Vec<u8>,
    ) -> Result<SignatureAlgorithm, CryptoError> {
        let verifying_key = VerifyingKey::from_cose(&CoseKeyBytes::from(verifying_key))?;
        let algorithm = verifying_key.algorithm();
        Ok(algorithm)
    }

    /// For a given signing identity (verifying key), this function verifies that the signing
    /// identity claimed ownership of the public key. This is a one-sided claim and merely shows
    /// that the signing identity has the intent to receive messages encrypted to the public
    /// key.
    pub fn verify_and_unwrap_signed_public_key(
        signed_public_key: Vec<u8>,
        verifying_key: Vec<u8>,
    ) -> Result<Vec<u8>, CryptoError> {
        let signed_public_key = SignedPublicKey::try_from(CoseSign1Bytes::from(signed_public_key))?;
        let verifying_key = VerifyingKey::from_cose(&CoseKeyBytes::from(verifying_key))?;
        signed_public_key
            .verify_and_unwrap(&verifying_key)
            .map(|public_key| public_key.to_der())?
            .map(|pk| pk.to_vec())
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

    const SIGNING_KEY_WRAPPING_KEY: &[u8] = &[
        40, 215, 110, 199, 183, 4, 182, 78, 213, 123, 251, 113, 72, 223, 57, 2, 3, 81, 136, 19, 88,
        78, 206, 176, 158, 251, 211, 84, 1, 199, 203, 142, 176, 227, 187, 136, 209, 79, 23, 13, 44,
        224, 90, 10, 191, 72, 22, 227, 171, 105, 107, 139, 24, 49, 9, 150, 103, 139, 151, 204, 165,
        121, 165, 71,
    ];
    const SIGNING_KEY: &[u8] = &[
        166, 1, 1, 2, 80, 123, 226, 102, 228, 194, 232, 71, 30, 183, 42, 219, 193, 50, 30, 21, 43,
        3, 39, 4, 130, 1, 2, 35, 88, 32, 148, 2, 66, 69, 169, 57, 129, 240, 37, 18, 225, 211, 207,
        133, 66, 143, 204, 238, 113, 152, 43, 112, 133, 173, 179, 17, 202, 135, 175, 237, 1, 59,
        32, 6,
    ];
    const VERIFYING_KEY: &[u8] = &[
        166, 1, 1, 2, 80, 123, 226, 102, 228, 194, 232, 71, 30, 183, 42, 219, 193, 50, 30, 21, 43,
        3, 39, 4, 129, 2, 32, 6, 33, 88, 32, 63, 70, 49, 37, 246, 232, 146, 144, 83, 224, 0, 17,
        111, 248, 16, 242, 69, 195, 84, 46, 39, 218, 55, 63, 90, 112, 148, 91, 224, 186, 122, 4,
    ];
    const PUBLIC_KEY: &[u8] = &[
        48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0,
        48, 130, 1, 10, 2, 130, 1, 1, 0, 173, 4, 54, 63, 125, 12, 254, 38, 115, 34, 95, 164, 148,
        115, 86, 140, 129, 74, 19, 70, 212, 212, 130, 163, 105, 249, 101, 120, 154, 46, 194, 250,
        229, 242, 156, 67, 109, 179, 187, 134, 59, 235, 60, 107, 144, 163, 35, 22, 109, 230, 134,
        243, 44, 243, 79, 84, 76, 11, 64, 56, 236, 167, 98, 26, 30, 213, 143, 105, 52, 92, 129, 92,
        88, 22, 115, 135, 63, 215, 79, 8, 11, 183, 124, 10, 73, 231, 170, 110, 210, 178, 22, 100,
        76, 75, 118, 202, 252, 204, 67, 204, 152, 6, 244, 208, 161, 146, 103, 225, 233, 239, 88,
        195, 88, 150, 230, 111, 62, 142, 12, 157, 184, 155, 34, 84, 237, 111, 11, 97, 56, 152, 130,
        14, 72, 123, 140, 47, 137, 5, 97, 166, 4, 147, 111, 23, 65, 78, 63, 208, 198, 50, 161, 39,
        80, 143, 100, 194, 37, 252, 194, 53, 207, 166, 168, 250, 165, 121, 9, 207, 90, 36, 213,
        211, 84, 255, 14, 205, 114, 135, 217, 137, 105, 232, 58, 169, 222, 10, 13, 138, 203, 16,
        12, 122, 72, 227, 95, 160, 111, 54, 200, 198, 143, 156, 15, 143, 196, 50, 150, 204, 144,
        255, 162, 248, 50, 28, 47, 66, 9, 83, 158, 67, 9, 50, 147, 174, 147, 200, 199, 238, 190,
        248, 60, 114, 218, 32, 209, 120, 218, 17, 234, 14, 128, 192, 166, 33, 60, 73, 227, 108,
        201, 41, 160, 81, 133, 171, 205, 221, 2, 3, 1, 0, 1,
    ];

    const SIGNED_PUBLIC_KEY: &[u8] = &[
        132, 88, 30, 164, 1, 39, 3, 24, 60, 4, 80, 123, 226, 102, 228, 194, 232, 71, 30, 183, 42,
        219, 193, 50, 30, 21, 43, 58, 0, 1, 56, 127, 1, 160, 89, 1, 78, 163, 105, 97, 108, 103,
        111, 114, 105, 116, 104, 109, 0, 109, 99, 111, 110, 116, 101, 110, 116, 70, 111, 114, 109,
        97, 116, 0, 105, 112, 117, 98, 108, 105, 99, 75, 101, 121, 89, 1, 38, 48, 130, 1, 34, 48,
        13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2,
        130, 1, 1, 0, 173, 4, 54, 63, 125, 12, 254, 38, 115, 34, 95, 164, 148, 115, 86, 140, 129,
        74, 19, 70, 212, 212, 130, 163, 105, 249, 101, 120, 154, 46, 194, 250, 229, 242, 156, 67,
        109, 179, 187, 134, 59, 235, 60, 107, 144, 163, 35, 22, 109, 230, 134, 243, 44, 243, 79,
        84, 76, 11, 64, 56, 236, 167, 98, 26, 30, 213, 143, 105, 52, 92, 129, 92, 88, 22, 115, 135,
        63, 215, 79, 8, 11, 183, 124, 10, 73, 231, 170, 110, 210, 178, 22, 100, 76, 75, 118, 202,
        252, 204, 67, 204, 152, 6, 244, 208, 161, 146, 103, 225, 233, 239, 88, 195, 88, 150, 230,
        111, 62, 142, 12, 157, 184, 155, 34, 84, 237, 111, 11, 97, 56, 152, 130, 14, 72, 123, 140,
        47, 137, 5, 97, 166, 4, 147, 111, 23, 65, 78, 63, 208, 198, 50, 161, 39, 80, 143, 100, 194,
        37, 252, 194, 53, 207, 166, 168, 250, 165, 121, 9, 207, 90, 36, 213, 211, 84, 255, 14, 205,
        114, 135, 217, 137, 105, 232, 58, 169, 222, 10, 13, 138, 203, 16, 12, 122, 72, 227, 95,
        160, 111, 54, 200, 198, 143, 156, 15, 143, 196, 50, 150, 204, 144, 255, 162, 248, 50, 28,
        47, 66, 9, 83, 158, 67, 9, 50, 147, 174, 147, 200, 199, 238, 190, 248, 60, 114, 218, 32,
        209, 120, 218, 17, 234, 14, 128, 192, 166, 33, 60, 73, 227, 108, 201, 41, 160, 81, 133,
        171, 205, 221, 2, 3, 1, 0, 1, 88, 64, 207, 18, 4, 242, 149, 31, 37, 255, 243, 62, 78, 46,
        12, 150, 134, 159, 69, 89, 62, 222, 132, 12, 177, 74, 155, 80, 154, 37, 77, 176, 19, 142,
        73, 4, 134, 242, 24, 56, 54, 38, 178, 59, 11, 118, 230, 159, 87, 91, 20, 237, 188, 186,
        216, 86, 189, 50, 46, 173, 117, 36, 54, 105, 216, 9,
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
    fn test_make_xchacha20_poly1305_key() {
        let key = PureCrypto::make_user_key_xchacha20_poly1305();
        assert!(key.len() > 64);
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
        let decapsulation_key = AsymmetricCryptoKey::from_pem(PEM_KEY).unwrap();
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
        let decapsulation_key = AsymmetricCryptoKey::from_pem(PEM_KEY).unwrap();
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
        let decapsulation_key = AsymmetricCryptoKey::from_pem(PEM_KEY).unwrap();
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
    fn test_key_algorithm_for_verifying_key() {
        let verifying_key =
            VerifyingKey::from_cose(&CoseKeyBytes::from(VERIFYING_KEY.to_vec())).unwrap();
        let algorithm =
            PureCrypto::key_algorithm_for_verifying_key(verifying_key.to_cose().to_vec()).unwrap();
        assert_eq!(algorithm, SignatureAlgorithm::Ed25519);
    }

    #[test]
    fn test_verifying_key_for_signing_key() {
        let wrapped_signing_key = PureCrypto::symmetric_encrypt_bytes(
            SIGNING_KEY.to_vec(),
            SIGNING_KEY_WRAPPING_KEY.to_vec(),
        )
        .unwrap();
        let verifying_key =
            VerifyingKey::from_cose(&CoseKeyBytes::from(VERIFYING_KEY.to_vec())).unwrap();
        let verifying_key_derived = PureCrypto::verifying_key_for_signing_key(
            wrapped_signing_key.to_string(),
            SIGNING_KEY_WRAPPING_KEY.to_vec(),
        )
        .unwrap();
        let verifying_key_derived =
            VerifyingKey::from_cose(&CoseKeyBytes::from(verifying_key_derived)).unwrap();
        assert_eq!(verifying_key.to_cose(), verifying_key_derived.to_cose());
    }

    #[test]
    fn test_verify_and_unwrap_signed_public_key() {
        let public_key = PureCrypto::verify_and_unwrap_signed_public_key(
            SIGNED_PUBLIC_KEY.to_vec(),
            VERIFYING_KEY.to_vec(),
        )
        .unwrap();
        assert_eq!(public_key, PUBLIC_KEY);
    }
}

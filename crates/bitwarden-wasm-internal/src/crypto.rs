use std::{rc::Rc, str::FromStr};

use bitwarden_core::{
    client::encryption_settings::EncryptionSettingsError,
    mobile::crypto::{
        InitOrgCryptoRequest, InitUserCryptoRequest, MakeKeyPairResponse,
        VerifyAsymmetricKeysRequest, VerifyAsymmetricKeysResponse,
    },
    Client,
};
use bitwarden_crypto::{EncString, KeyDecryptable, KeyEncryptable, SymmetricCryptoKey};
use bitwarden_error::prelude::*;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum PureCryptoError {
    #[error("Cryptography error, {0}")]
    Crypto(#[from] bitwarden_crypto::CryptoError),
}

pub mod pure_crypto {
    use std::collections::HashMap;

    use bitwarden_crypto::DecryptedWithAdditionalData;
    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(tsify_next::Tsify, Serialize, Deserialize)]
    #[tsify(into_wasm_abi, from_wasm_abi)]
    pub struct DecryptedString {
        pub clear_text: String,
        pub additional_data: HashMap<String, String>,
    }

    #[derive(tsify_next::Tsify, Serialize, Deserialize)]
    #[tsify(into_wasm_abi, from_wasm_abi)]
    pub struct DecryptedBytes {
        pub clear_bytes: Vec<u8>,
        pub additional_data: HashMap<String, String>,
    }

    #[derive(tsify_next::Tsify, Serialize, Deserialize)]
    #[tsify(into_wasm_abi, from_wasm_abi)]
    pub struct EncryptOptions {
        pub additional_data: Option<HashMap<String, String>>,
    }

    impl TryFrom<DecryptedBytes> for DecryptedString {
        type Error = PureCryptoError;
        fn try_from(decrypted_bytes: DecryptedBytes) -> Result<Self, PureCryptoError> {
            Ok(Self {
                clear_text: String::from_utf8(decrypted_bytes.clear_bytes)
                    .map_err(|_| bitwarden_crypto::CryptoError::InvalidUtf8String)?,
                additional_data: decrypted_bytes.additional_data,
            })
        }
    }

    impl From<DecryptedWithAdditionalData> for DecryptedBytes {
        fn from(decrypted: DecryptedWithAdditionalData) -> Self {
            Self {
                clear_bytes: decrypted.clear_bytes().to_vec(),
                additional_data: decrypted.additional_data().clone(),
            }
        }
    }

    pub fn symmetric_decrypt(
        enc_string: String,
        key_b64: String,
    ) -> Result<DecryptedString, PureCryptoError> {
        let dec = symmetric_decrypt_to_bytes(enc_string, key_b64)?;
        Ok(dec.try_into()?)
    }

    pub fn symmetric_decrypt_to_bytes(
        enc_string: String,
        key_b64: String,
    ) -> Result<DecryptedBytes, PureCryptoError> {
        let enc_string = EncString::from_str(&enc_string)?;
        let key = SymmetricCryptoKey::try_from(key_b64)?;

        let dec: DecryptedWithAdditionalData = enc_string.decrypt_with_key(&key)?;
        Ok(dec.into())
    }

    pub fn symmetric_encrypt(plain: String, key_b64: String) -> Result<String, PureCryptoError> {
        let key = SymmetricCryptoKey::try_from(key_b64)?;

        let encrypted: EncString = plain.encrypt_with_key(&key)?;
        Ok(encrypted.to_string())
    }
}

#[wasm_bindgen]
pub struct ClientCrypto(Rc<Client>);

impl ClientCrypto {
    pub fn new(client: Rc<Client>) -> Self {
        Self(client)
    }
}

#[wasm_bindgen]
impl ClientCrypto {
    /// Initialization method for the user crypto. Needs to be called before any other crypto
    /// operations.
    pub async fn initialize_user_crypto(
        &self,
        req: InitUserCryptoRequest,
    ) -> Result<(), EncryptionSettingsError> {
        self.0.crypto().initialize_user_crypto(req).await
    }

    /// Initialization method for the organization crypto. Needs to be called after
    /// `initialize_user_crypto` but before any other crypto operations.
    pub async fn initialize_org_crypto(
        &self,
        req: InitOrgCryptoRequest,
    ) -> Result<(), EncryptionSettingsError> {
        self.0.crypto().initialize_org_crypto(req).await
    }

    /// Generates a new key pair and encrypts the private key with the provided user key.
    /// Crypto initialization not required.
    pub fn make_key_pair(
        &self,
        user_key: String,
    ) -> Result<MakeKeyPairResponse, bitwarden_core::Error> {
        self.0.crypto().make_key_pair(user_key)
    }

    /// Verifies a user's asymmetric keys by decrypting the private key with the provided user
    /// key. Returns if the private key is decryptable and if it is a valid matching key.
    /// Crypto initialization not required.
    pub fn verify_asymmetric_keys(
        &self,
        request: VerifyAsymmetricKeysRequest,
    ) -> Result<VerifyAsymmetricKeysResponse, bitwarden_core::Error> {
        self.0.crypto().verify_asymmetric_keys(request)
    }
}

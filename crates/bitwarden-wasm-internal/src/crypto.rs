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
use log::info;
use wasm_bindgen::prelude::*;
use thiserror::Error;

#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum PureCryptoError {
    #[error("Cryptography error, {0}")]
    Crypto(#[from] bitwarden_crypto::CryptoError),
}

#[wasm_bindgen]
pub struct PureCrypto;

impl PureCrypto {
    pub fn new() -> Self {
        Self
    }
}

#[wasm_bindgen]
impl PureCrypto {
    pub fn symmetric_decrypt(&self, enc_string: String, key_b64: String) -> Result<String, PureCryptoError> {
        let dec= self.symmetric_decrypt_to_bytes(enc_string, key_b64)?;
        Ok(String::from_utf8(dec).map_err(|_| bitwarden_crypto::CryptoError::InvalidUtf8String)?)
    }

    pub fn symmetric_decrypt_to_bytes(&self, enc_string: String, key_b64: String) -> Result<Vec<u8>, PureCryptoError> {
        let enc_string = EncString::from_str(&enc_string)?;
        let key = SymmetricCryptoKey::try_from(key_b64)?;

        let decrypted: Vec<u8> = enc_string.decrypt_with_key(&key)?;
        Ok(decrypted)
    }

    pub fn symmetric_encrypt(&self, plain: String, key_b64: String) -> Result<String, PureCryptoError> {
        let key = SymmetricCryptoKey::try_from(key_b64)?;

        let encrypted: EncString = plain.encrypt_with_key(&key)?;
        Ok(encrypted.to_string())
    }
}

#[wasm_bindgen]
pub struct CryptoClient(Rc<Client>);

impl CryptoClient {
    pub fn new(client: Rc<Client>) -> Self {
        Self(client)
    }
}

#[wasm_bindgen]
impl CryptoClient {
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

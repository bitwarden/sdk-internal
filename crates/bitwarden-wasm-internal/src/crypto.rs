use std::rc::Rc;

use bitwarden_core::{
    client::encryption_settings::EncryptionSettingsError,
    mobile::crypto::{
        InitOrgCryptoRequest, InitUserCryptoRequest, MakeKeyPairResponse,
        VerifyAsymmetricKeysRequest, VerifyAsymmetricKeysResponse,
    },
    Client,
};
use bitwarden_crypto::CryptoError;
use bitwarden_error::bitwarden_error;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum PureCryptoError {
    #[error("Cryptography error, {0}")]
    Crypto(#[from] bitwarden_crypto::CryptoError),
}

pub mod pure_crypto {
    use std::str::FromStr;

    use bitwarden_crypto::{EncString, KeyDecryptable, KeyEncryptable, SymmetricCryptoKey};

    use super::*;

    pub fn symmetric_decrypt(
        enc_string: String,
        key_b64: String,
    ) -> Result<String, PureCryptoError> {
        let enc_string = EncString::from_str(&enc_string)?;
        let key = SymmetricCryptoKey::try_from(key_b64)?;

        Ok(enc_string.decrypt_with_key(&key)?)
    }

    pub fn symmetric_decrypt_to_bytes(
        enc_string: String,
        key_b64: String,
    ) -> Result<Vec<u8>, PureCryptoError> {
        let enc_string = EncString::from_str(&enc_string)?;
        let key = SymmetricCryptoKey::try_from(key_b64)?;

        Ok(enc_string.decrypt_with_key(&key)?)
    }

    pub fn symmetric_decrypt_array_buffer(
        enc_bytes: Vec<u8>,
        key_b64: String,
    ) -> Result<Vec<u8>, PureCryptoError> {
        let enc_string = EncString::from_buffer(&enc_bytes)?;
        let key = SymmetricCryptoKey::try_from(key_b64)?;

        Ok(enc_string.decrypt_with_key(&key)?)
    }

    pub fn symmetric_encrypt(plain: &[u8], key_b64: String) -> Result<EncString, PureCryptoError> {
        let key = SymmetricCryptoKey::try_from(key_b64)?;

        let encrypted: EncString = plain.encrypt_with_key(&key)?;
        Ok(encrypted)
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
    pub fn make_key_pair(&self, user_key: String) -> Result<MakeKeyPairResponse, CryptoError> {
        self.0.crypto().make_key_pair(user_key)
    }

    /// Verifies a user's asymmetric keys by decrypting the private key with the provided user
    /// key. Returns if the private key is decryptable and if it is a valid matching key.
    /// Crypto initialization not required.
    pub fn verify_asymmetric_keys(
        &self,
        request: VerifyAsymmetricKeysRequest,
    ) -> Result<VerifyAsymmetricKeysResponse, CryptoError> {
        self.0.crypto().verify_asymmetric_keys(request)
    }
}

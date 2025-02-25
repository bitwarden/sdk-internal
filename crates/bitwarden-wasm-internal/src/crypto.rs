use std::{rc::Rc, str::FromStr};

use bitwarden_core::{
    client::encryption_settings::EncryptionSettingsError,
    mobile::crypto::{
        InitOrgCryptoRequest, InitUserCryptoRequest, MakeKeyPairResponse,
        VerifyAsymmetricKeysRequest, VerifyAsymmetricKeysResponse,
    },
    Client,
};
use bitwarden_crypto::{
    CryptoError, EncString, KeyDecryptable, KeyEncryptable, SymmetricCryptoKey,
};
use bitwarden_error::bitwarden_error;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum PureCryptoError {
    #[error("Cryptography error, {0}")]
    Crypto(#[from] bitwarden_crypto::CryptoError),
}

#[wasm_bindgen]
pub struct PureCrypto {}

#[wasm_bindgen]
impl PureCrypto {
    /// Stopgap method providing access to decryption through the SDKs handling of
    /// [bitwarden_crypto::EncString] and [bitwarden_crypto::SymmetricCryptoKey].
    ///
    /// This method is intended for use in the javascript clients at the EncryptService layer and
    /// should not be used elsewhere.
    pub fn symmetric_decrypt(
        enc_string: String,
        key_b64: String,
    ) -> Result<String, PureCryptoError> {
        let enc_string = EncString::from_str(&enc_string)?;
        let key = SymmetricCryptoKey::try_from(key_b64)?;

        Ok(enc_string.decrypt_with_key(&key)?)
    }

    /// Stopgap method providing access to decryption through the SDKs handling of
    /// [bitwarden_crypto::EncString] and [bitwarden_crypto::SymmetricCryptoKey]
    ///
    /// This method is intended for use in the javascript clients at the EncryptService layer and
    /// should not be used elsewhere.
    pub fn symmetric_decrypt_to_bytes(
        enc_string: String,
        key_b64: String,
    ) -> Result<Vec<u8>, PureCryptoError> {
        let enc_string = EncString::from_str(&enc_string)?;
        let key = SymmetricCryptoKey::try_from(key_b64)?;

        Ok(enc_string.decrypt_with_key(&key)?)
    }

    /// Stopgap method providing access to decryption through the SDKs handling of
    /// [bitwarden_crypto::EncString]
    ///
    /// Blob data uploaded for file storage has a different format that typical [EncString]
    /// serialization. Handles `EncArrayBuffer` data of the form `[u8]` with the type being the
    /// first byte, the iv the next 16, an optional mac of length 32 (depending on the first
    /// byte), and data following. This method will Err if decrypting a the bytes of a typically
    /// serialized `EncString`.
    ///
    /// This method is intended for use in the javascript clients at the EncryptService layer and
    /// should not be used elsewhere.
    pub fn symmetric_decrypt_array_buffer(
        enc_bytes: Vec<u8>,
        key_b64: String,
    ) -> Result<Vec<u8>, PureCryptoError> {
        let enc_string = EncString::from_buffer(&enc_bytes)?;
        let key = SymmetricCryptoKey::try_from(key_b64)?;

        Ok(enc_string.decrypt_with_key(&key)?)
    }

    /// Stopgap method providing access to encryption through the SDKs handling of
    /// [bitwarden_crypto::EncString]
    ///
    /// Encrypts cleartext strings to string-serialized (base64) [EncString]s.
    ///
    /// This method is intended for use in the javascript clients at the EncryptService layer and
    /// should not be used elsewhere.
    pub fn symmetric_encrypt(plain: String, key_b64: String) -> Result<String, PureCryptoError> {
        let key = SymmetricCryptoKey::try_from(key_b64)?;

        Ok(plain.encrypt_with_key(&key)?.to_string())
    }

    /// Stopgap method providing access to encryption through the SDKs handling of
    /// [bitwarden_crypto::EncString]
    ///
    /// Encrypts cleartext strings to byte-serialized [EncString]s.
    ///
    /// This method is intended for use in the javascript clients at the EncryptService layer and
    /// should not be used elsewhere.
    pub fn symmetric_encrypt_to_array_buffer(
        plain: Vec<u8>,
        key_b64: String,
    ) -> Result<Vec<u8>, PureCryptoError> {
        let key = SymmetricCryptoKey::try_from(key_b64)?;
        Ok(plain.encrypt_with_key(&key)?.to_buffer()?)
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

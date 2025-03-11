use std::rc::Rc;

use bitwarden_core::{
    client::encryption_settings::EncryptionSettingsError,
    mobile::crypto::{
        InitOrgCryptoRequest, InitUserCryptoRequest, MakeKeyPairResponse,
        VerifyAsymmetricKeysRequest, VerifyAsymmetricKeysResponse,
    },
    Client,
};
use bitwarden_crypto::{opaque_ke, CryptoError, OpaqueError};
use wasm_bindgen::prelude::*;

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

    pub fn opaque_register_start(
        &self,
        password: &[u8],
    ) -> Result<opaque_ke::RegistrationStartResult, OpaqueError> {
        self.0.crypto().opaque_register_start(password)
    }

    pub fn opaque_register_finish(
        &self,
        registration_start: &[u8],
        registration_finish: &[u8],
        password: &[u8],
        configuration: &opaque_ke::CipherConfiguration,
    ) -> Result<opaque_ke::RegistrationFinishResult, OpaqueError> {
        self.0.crypto().opaque_register_finish(
            registration_start,
            registration_finish,
            password,
            configuration,
        )
    }

    pub fn opaque_login_start(
        &self,
        password: &[u8],
    ) -> Result<opaque_ke::LoginStartResult, OpaqueError> {
        self.0.crypto().opaque_login_start(password)
    }

    pub fn opaque_login_finish(
        &self,
        start: &[u8],
        finish: &[u8],
        password: &[u8],
        configuration: &opaque_ke::CipherConfiguration,
    ) -> Result<opaque_ke::LoginFinishResult, OpaqueError> {
        self.0
            .crypto()
            .opaque_login_finish(start, finish, password, configuration)
    }
}

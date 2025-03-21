use std::rc::Rc;

use bitwarden_core::{
    client::encryption_settings::EncryptionSettingsError,
    mobile::crypto::{
        InitOrgCryptoRequest, InitUserCryptoRequest, MakeKeyPairResponse,
        VerifyAsymmetricKeysRequest, VerifyAsymmetricKeysResponse,
    },
    Client,
};
use bitwarden_crypto::{
    opaque_ke, rotateable_keyset::RotateableKeyset, CryptoError, OpaqueError, SymmetricCryptoKey,
};
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

    /// Starts an opaque registration based on the provided password and cipher configuration
    pub fn opaque_register_start(
        &self,
        password: &str,
        config: &opaque_ke::types::CipherConfiguration,
    ) -> Result<opaque_ke::types::ClientRegistrationStartResult, OpaqueError> {
        self.0.crypto().opaque_register_start(password, config)
    }

    /// Finishes an opaque registration based on the provided password, cipher configuration
    /// registration response from the server and client state
    pub fn opaque_register_finish(
        &self,
        password: &str,
        config: &opaque_ke::types::CipherConfiguration,
        registration_response: &[u8],
        state: &[u8],
    ) -> Result<opaque_ke::types::ClientRegistrationFinishResult, OpaqueError> {
        self.0
            .crypto()
            .opaque_register_finish(password, config, registration_response, state)
    }

    /// Starts an opaque authentication based on the provided password and cipher configuration
    pub fn opaque_login_start(
        &self,
        password: &str,
        config: &opaque_ke::types::CipherConfiguration,
    ) -> Result<opaque_ke::types::ClientLoginStartResult, OpaqueError> {
        self.0.crypto().opaque_login_start(password, config)
    }

    /// Finishes an opaque authentication based on the provided password, cipher configuration,
    /// login response from the server and client state
    pub fn opaque_login_finish(
        &self,
        password: &str,
        config: &opaque_ke::types::CipherConfiguration,
        login_response: &[u8],
        state: &[u8],
    ) -> Result<opaque_ke::types::ClientLoginFinishResult, OpaqueError> {
        self.0
            .crypto()
            .opaque_login_finish(password, config, login_response, state)
    }

    /// Creates a new rotateable keyset from an export key and an encapsulated key
    pub fn create_rotateablekeyset_from_exportkey(
        &self,
        export_key: &mut [u8],
        encapsulated_key: &[u8],
    ) -> Result<RotateableKeyset, CryptoError> {
        let key = SymmetricCryptoKey::try_from(encapsulated_key.to_vec())?;
        self.0
            .crypto()
            .create_rotateablekeyset_from_exportkey(export_key, &key)
    }

    /// Decapsulates a key from a rotateable keyset
    pub fn decapsulate_key_from_rotateablekeyset(
        &self,
        rotateable_keyset: RotateableKeyset,
        encapsulating_key: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Ok(self
            .0
            .crypto()
            .decapsulate_key_from_rotateablekeyset(rotateable_keyset, encapsulating_key)?
            .to_vec())
    }
}

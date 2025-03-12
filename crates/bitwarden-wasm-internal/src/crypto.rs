use std::rc::Rc;

use bitwarden_core::{
    client::encryption_settings::EncryptionSettingsError,
    mobile::crypto::{
        InitOrgCryptoRequest, InitUserCryptoRequest, MakeKeyPairResponse,
        VerifyAsymmetricKeysRequest, VerifyAsymmetricKeysResponse,
    },
    Client,
};
use bitwarden_crypto::{opaque_ke, rotateable_keyset::{RotateableKeyset}, CryptoError, OpaqueError, SymmetricCryptoKey};
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
        registration_start_state: &[u8],
        registration_start_response: &[u8],
        password: &[u8],
        configuration: &opaque_ke::CipherConfiguration,
        userkey: &[u8],
    ) -> Result<opaque_ke::RegistrationFinishResult, OpaqueError> {
        let userkey = SymmetricCryptoKey::try_from(userkey.to_vec())
            .map_err(|_| OpaqueError::Message("Invalid user key".to_string()))?;
        self.0.crypto().opaque_register_finish(
            registration_start_state,
            registration_start_response,
            password,
            configuration,
            userkey,
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
        login_start_state: &[u8],
        login_start_response: &[u8],
        password: &[u8],
        configuration: &opaque_ke::CipherConfiguration,
    ) -> Result<opaque_ke::LoginFinishResult, OpaqueError> {
        self.0.crypto().opaque_login_finish(
            login_start_state,
            login_start_response,
            password,
            configuration,
        )
    }

    pub fn decapsulate_key_from_rotateablekeyset(
        &self,
        rotateable_keyset: RotateableKeyset,
        encapsulating_key: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let key = SymmetricCryptoKey::try_from(encapsulating_key.to_vec())?;
        Ok(self.0.crypto().decapsulate_key_from_rotateablekeyset(rotateable_keyset, &key)?.to_vec())
    }

}

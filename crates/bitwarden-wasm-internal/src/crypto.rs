use bitwarden_core::{
    client::encryption_settings::EncryptionSettingsError,
    mobile::crypto::{
        InitOrgCryptoRequest, InitUserCryptoRequest, MakeKeyPairResponse,
        MakeUserSigningKeysResponse, VerifyAsymmetricKeysRequest, VerifyAsymmetricKeysResponse,
    },
};
use bitwarden_crypto::CryptoError;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct CryptoClient(bitwarden_core::mobile::CryptoClient);

impl CryptoClient {
    pub fn new(client: bitwarden_core::mobile::CryptoClient) -> Self {
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
        self.0.initialize_user_crypto(req).await
    }

    /// Initialization method for the organization crypto. Needs to be called after
    /// `initialize_user_crypto` but before any other crypto operations.
    pub async fn initialize_org_crypto(
        &self,
        req: InitOrgCryptoRequest,
    ) -> Result<(), EncryptionSettingsError> {
        self.0.initialize_org_crypto(req).await
    }

    /// Generates a new key pair and encrypts the private key with the provided user key.
    /// Crypto initialization not required.
    pub fn make_key_pair(&self, user_key: String) -> Result<MakeKeyPairResponse, CryptoError> {
        self.0.make_key_pair(user_key)
    }

    /// Verifies a user's asymmetric keys by decrypting the private key with the provided user
    /// key. Returns if the private key is decryptable and if it is a valid matching key.
    /// Crypto initialization not required.
    pub fn verify_asymmetric_keys(
        &self,
        request: VerifyAsymmetricKeysRequest,
    ) -> Result<VerifyAsymmetricKeysResponse, CryptoError> {
        self.0.verify_asymmetric_keys(request)
    }

    /// Generates a new signing key pair and encrypts the signing key with the provided symmetric
    /// key. Crypto initialization not required.
    pub fn make_signing_keys(&self) -> Result<MakeUserSigningKeysResponse, CryptoError> {
        self.0.make_signing_keys()
    }

    pub fn make_signed_public_key_ownership_claim(&self) -> Result<String, CryptoError> {
        self.0.make_signed_public_key_ownership_claim()
    }

    pub fn get_wrapped_user_signing_key(
        &self,
        new_user_key: String,
    ) -> Result<String, CryptoError> {
        self.0.get_wrapped_user_signing_key(new_user_key)
            .map(|enc_string| enc_string.to_string())
    }
}

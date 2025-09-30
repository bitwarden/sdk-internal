use crate::{
    Client,
    platform::{
        FingerprintError, FingerprintRequest, SecretVerificationRequest, UserApiKeyError,
        UserApiKeyResponse, UserFingerprintError,
        generate_fingerprint::{generate_fingerprint, generate_user_fingerprint},
        get_user_api_key,
    },
};

/// Wrapper for platform specific functionality.
pub struct PlatformClient {
    pub(crate) client: Client,
}

impl PlatformClient {
    /// Fingerprint (public key)
    pub fn fingerprint(&self, input: &FingerprintRequest) -> Result<String, FingerprintError> {
        generate_fingerprint(input)
    }

    /// Fingerprint using logged in user's public key
    pub fn user_fingerprint(
        self,
        fingerprint_material: String,
    ) -> Result<String, UserFingerprintError> {
        generate_user_fingerprint(&self.client, fingerprint_material)
    }

    /// Test function for performing API requests to fetch a users api key.
    pub async fn get_user_api_key(
        &mut self,
        input: SecretVerificationRequest,
    ) -> Result<UserApiKeyResponse, UserApiKeyError> {
        get_user_api_key(&self.client, &input).await
    }

    /// Access to state functionality.
    pub fn state(&self) -> super::StateClient {
        super::StateClient {
            client: self.client.clone(),
        }
    }
}

impl Client {
    /// Access to platform functionality.
    pub fn platform(&self) -> PlatformClient {
        PlatformClient {
            client: self.clone(),
        }
    }
}

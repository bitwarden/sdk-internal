use crate::{
    platform::{
        generate_fingerprint::{generate_fingerprint, generate_user_fingerprint},
        get_user_api_key, FingerprintError, FingerprintRequest, SecretVerificationRequest,
        UserApiKeyError, UserApiKeyResponse, UserFingerprintError,
    },
    Client,
};

/// Wrapper for platform specific functionality.
pub struct PlatformClient<'a> {
    pub(crate) client: &'a Client,
}

#[allow(missing_docs)]
impl PlatformClient<'_> {
    pub fn fingerprint(&self, input: &FingerprintRequest) -> Result<String, FingerprintError> {
        generate_fingerprint(input)
    }

    pub fn user_fingerprint(
        self,
        fingerprint_material: String,
    ) -> Result<String, UserFingerprintError> {
        generate_user_fingerprint(self.client, fingerprint_material)
    }

    pub async fn get_user_api_key(
        &mut self,
        input: SecretVerificationRequest,
    ) -> Result<UserApiKeyResponse, UserApiKeyError> {
        get_user_api_key(self.client, &input).await
    }
}

impl<'a> Client {
    /// Access to platform functionality.
    pub fn platform(&'a self) -> PlatformClient<'a> {
        PlatformClient { client: self }
    }
}

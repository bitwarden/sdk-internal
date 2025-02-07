use super::{
    generate_fingerprint::{generate_fingerprint, generate_user_fingerprint},
    get_user_api_key, FingerprintError, FingerprintRequest, FingerprintResponse,
    SecretVerificationRequest, UserApiKeyResponse, UserFingerprintError,
};
use crate::{error::Result, Client};

pub struct PlatformClient<'a> {
    pub(crate) client: &'a Client,
}

impl PlatformClient<'_> {
    pub fn fingerprint(
        &self,
        input: &FingerprintRequest,
    ) -> Result<FingerprintResponse, FingerprintError> {
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
    ) -> Result<UserApiKeyResponse> {
        get_user_api_key(self.client, &input).await
    }
}

impl<'a> Client {
    pub fn platform(&'a self) -> PlatformClient<'a> {
        PlatformClient { client: self }
    }
}

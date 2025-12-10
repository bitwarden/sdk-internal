use bitwarden_api_identity::models::PasswordPreloginRequestModel;
use bitwarden_core::{ApiError, MissingFieldError};
use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::identity::{IdentityClient, login_via_password::PasswordPreloginResponse};

/// Error type for password prelogin operations
#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum PasswordPreloginError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
}

impl IdentityClient {
    /// Retrieves the data required before authenticating with a password.
    /// This includes the user's KDF configuration needed to properly derive the master key.
    ///
    /// # Arguments
    /// * `email` - The user's email address
    ///
    /// # Returns
    /// * `PreloginPasswordData` - Contains the KDF configuration for the user
    pub async fn get_password_prelogin_data(
        &self,
        email: String,
    ) -> Result<PasswordPreloginResponse, PasswordPreloginError> {
        let request_model = PasswordPreloginRequestModel::new(email);
        let config = self.client.internal.get_api_configurations().await;
        let response = config
            .identity_client
            .accounts_api()
            .post_password_prelogin(Some(request_model))
            .await
            .map_err(ApiError::from)?;

        Ok(PasswordPreloginResponse::try_from(response)?)
    }
}

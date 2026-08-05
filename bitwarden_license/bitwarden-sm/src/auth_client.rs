//! Secrets Manager auth client, providing SM-specific authentication methods.

use bitwarden_auth::login::access_token::{AccessTokenLoginRequest, AccessTokenLoginResponse};
use bitwarden_core::auth::login::LoginError;

use crate::client::SecretsManagerClient;

/// Sub-client for Secrets Manager authentication.
pub struct SmAuthClient {
    client: SecretsManagerClient,
}

impl SmAuthClient {
    pub(crate) fn new(client: SecretsManagerClient) -> Self {
        Self { client }
    }

    /// Log in with an access token.
    pub async fn login_access_token(
        &self,
        input: &AccessTokenLoginRequest,
    ) -> Result<AccessTokenLoginResponse, LoginError> {
        crate::login_access_token::login_access_token(&self.client, input).await
    }
}

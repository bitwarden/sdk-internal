use bitwarden_api_api::Configuration;
use serde::{Deserialize, Serialize};

use crate::auth::{api::response::IdentityTokenResponse, login::LoginError};

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct RenewTokenRequest {
    grant_type: String,
    refresh_token: String,
    client_id: String,
}

impl RenewTokenRequest {
    pub(crate) fn new(refresh_token: String, client_id: String) -> Self {
        Self {
            refresh_token,
            client_id,
            grant_type: "refresh_token".to_string(),
        }
    }

    pub(crate) async fn send(
        &self,
        identity_config: &Configuration,
    ) -> Result<IdentityTokenResponse, LoginError> {
        super::send_identity_connect_request(identity_config, &self).await
    }
}

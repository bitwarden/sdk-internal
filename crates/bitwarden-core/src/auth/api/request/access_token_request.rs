use bitwarden_api_api::Configuration;
use serde::{Deserialize, Serialize};
use tracing::debug;
use uuid::Uuid;

use crate::auth::{api::response::IdentityTokenResponse, login::LoginError};

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct AccessTokenRequest {
    scope: String,
    client_id: String,
    client_secret: String,
    grant_type: String,
}

impl AccessTokenRequest {
    pub(crate) fn new(access_token_id: Uuid, client_secret: &String) -> Self {
        let obj = Self {
            scope: "api.secrets".to_string(),
            client_id: access_token_id.to_string(),
            client_secret: client_secret.to_string(),
            grant_type: "client_credentials".to_string(),
        };
        debug!(?obj, "initializing");
        obj
    }

    pub(crate) async fn send(
        &self,
        identity_config: &Configuration,
    ) -> Result<IdentityTokenResponse, LoginError> {
        super::send_identity_connect_request(identity_config, &self).await
    }
}

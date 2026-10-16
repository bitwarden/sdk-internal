use bitwarden_api_api::Configuration;
use serde::{Deserialize, Serialize};

use crate::auth::{api::response::IdentityTokenResponse, login::LoginError};

#[derive(Serialize, Deserialize)]
pub(crate) struct ApiTokenRequest {
    scope: String,
    client_id: String,
    client_secret: String,
    #[serde(rename = "deviceType")]
    device_type: u8,
    #[serde(rename = "deviceIdentifier")]
    device_identifier: String,
    #[serde(rename = "deviceName")]
    device_name: String,
    grant_type: String,
}

impl ApiTokenRequest {
    pub(crate) fn new(client_id: &String, client_secret: &String) -> Self {
        Self {
            scope: "api".to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            device_type: 10,
            device_identifier: "b86dd6ab-4265-4ddf-a7f1-eb28d5677f33".to_string(),
            device_name: "firefox".to_string(),
            grant_type: "client_credentials".to_string(),
        }
    }

    pub(crate) async fn send(
        &self,
        identity_config: &Configuration,
    ) -> Result<IdentityTokenResponse, LoginError> {
        super::send_identity_connect_request(identity_config, &self).await
    }
}

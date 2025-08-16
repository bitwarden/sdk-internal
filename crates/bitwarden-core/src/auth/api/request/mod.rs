#[cfg(feature = "secrets")]
mod access_token_request;
#[cfg(feature = "secrets")]
pub(crate) use access_token_request::*;

mod api_token_request;
pub(crate) use api_token_request::*;

#[cfg(feature = "internal")]
mod password_token_request;
#[cfg(feature = "internal")]
pub(crate) use password_token_request::*;

mod renew_token_request;
pub(crate) use renew_token_request::*;

mod auth_request_token_request;
#[cfg(feature = "internal")]
pub(crate) use auth_request_token_request::*;

use crate::{
    auth::{
        api::response::{parse_identity_response, IdentityTokenResponse},
        login::LoginError,
    },
    client::ApiConfigurations,
    ApiError,
};

async fn send_identity_connect_request(
    configurations: &ApiConfigurations,
    body: impl serde::Serialize,
) -> Result<IdentityTokenResponse, LoginError> {
    let mut request = configurations
        .identity
        .client
        .post(format!(
            "{}/connect/token",
            &configurations.identity.base_path
        ))
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded; charset=utf-8",
        )
        .header(reqwest::header::ACCEPT, "application/json")
        .header("Device-Type", configurations.device_type as usize);

    if let Some(ref user_agent) = configurations.identity.user_agent {
        request = request.header(reqwest::header::USER_AGENT, user_agent.clone());
    }

    let response = request
        .body(serde_qs::to_string(&body).expect("Serialize should be infallible"))
        .send()
        .await
        .map_err(ApiError::from)?;

    let status = response.status();
    let text = response.text().await.map_err(ApiError::from)?;

    parse_identity_response(status, text)
}

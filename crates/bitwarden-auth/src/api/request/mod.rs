//! Request models for Identity API endpoints that cannot be auto-generated
//! (e.g., connect/token endpoints) and are shared across multiple clients.
//!
//! For standard controller endpoints, use the `bitwarden-api-identity` crate.

mod access_token_request;
pub(crate) use access_token_request::*;
use bitwarden_api_api::Configuration;
use bitwarden_core::{ApiError, auth::login::LoginError};

use super::response::{IdentityTokenResponse, parse_identity_response};

pub(crate) async fn send_identity_connect_request(
    identity_config: &Configuration,
    body: impl serde::Serialize,
) -> Result<IdentityTokenResponse, LoginError> {
    let response = identity_config
        .client
        .post(format!("{}/connect/token", &identity_config.base_path))
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded; charset=utf-8",
        )
        .header(reqwest::header::ACCEPT, "application/json")
        .body(serde_qs::to_string(&body).expect("Serialize should be infallible"))
        .send()
        .await
        .map_err(ApiError::from)?;

    let status = response.status();
    let text = response.text().await.map_err(ApiError::from)?;

    parse_identity_response(status, text)
}

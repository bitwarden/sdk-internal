//! Response models for Identity API endpoints that cannot be auto-generated
//! (e.g., connect/token endpoints) and are shared across multiple clients.
//!
//! For standard controller endpoints, use the `bitwarden-api-identity` crate.

#![allow(missing_docs)]

use bitwarden_api_api::ResponseContent;
use bitwarden_core::auth::{IdentityTokenFailResponse, login::LoginError};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum IdentityTokenResponse {
    Authenticated(IdentityTokenSuccessResponse),
    Payload(IdentityTokenPayloadResponse),
    Refreshed(IdentityTokenRefreshResponse),
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct IdentityTokenPayloadResponse {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    #[allow(dead_code)]
    token_type: String,
    #[allow(dead_code)]
    scope: String,
    pub encrypted_payload: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct IdentityTokenRefreshResponse {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    #[allow(dead_code)]
    token_type: String,
    #[allow(dead_code)]
    scope: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct IdentityTokenSuccessResponse {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    #[allow(dead_code)]
    token_type: String,
}

pub(crate) fn parse_identity_response(
    status: StatusCode,
    response: String,
) -> Result<IdentityTokenResponse, LoginError> {
    // Payload response has `encrypted_payload` — try it first to avoid ambiguity with
    // IdentityTokenSuccessResponse (which also has `access_token`).
    if let Ok(r) = serde_json::from_str::<IdentityTokenPayloadResponse>(&response) {
        return Ok(IdentityTokenResponse::Payload(r));
    }
    if let Ok(r) = serde_json::from_str::<IdentityTokenSuccessResponse>(&response) {
        return Ok(IdentityTokenResponse::Authenticated(r));
    }
    if let Ok(r) = serde_json::from_str::<IdentityTokenRefreshResponse>(&response) {
        return Ok(IdentityTokenResponse::Refreshed(r));
    }
    // Surface the server-provided failure reason. A structured fail response yields a clean
    // message via `IdentityFail`; anything else falls back to the raw response body.
    if let Ok(r) = serde_json::from_str::<IdentityTokenFailResponse>(&response) {
        return Err(LoginError::IdentityFail(r));
    }
    Err(LoginError::Api(
        ResponseContent {
            status,
            message: response,
        }
        .into(),
    ))
}

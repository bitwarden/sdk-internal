//! Public API for Secrets Manager access-token HTTP requests.
//!
//! This module re-exports the types and function needed by `bitwarden-sm` to
//! perform the access-token login flow without exposing the full `api` module.

use bitwarden_api_api::Configuration;
use bitwarden_core::auth::login::LoginError;
use uuid::Uuid;

pub use crate::api::response::{
    IdentityTokenPayloadResponse, IdentityTokenRefreshResponse, IdentityTokenResponse,
    IdentityTokenSuccessResponse,
};

/// Send an access-token credential exchange request to the Identity endpoint.
///
/// Returns an [`IdentityTokenResponse`] on success.
pub async fn send_access_token_request(
    identity_config: &Configuration,
    access_token_id: Uuid,
    client_secret: &String,
) -> Result<IdentityTokenResponse, LoginError> {
    crate::api::request::AccessTokenRequest::new(access_token_id, client_secret)
        .send(identity_config)
        .await
}

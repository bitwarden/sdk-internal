//! Token renewal module.

mod middleware;
mod password_manager_token_handler;
#[cfg(test)]
pub(super) mod test_utils;

use bitwarden_core::auth::login::LoginError;
pub use middleware::{MiddlewareExt, MiddlewareWrapper};
pub use password_manager_token_handler::PasswordManagerTokenHandler;

pub use crate::service_account_login_method::ServiceAccountLoginMethod;
use crate::{
    service_account_login_method::ServiceAccountLoginMethod as SmLoginMethod,
    sm_request::{IdentityTokenResponse, send_access_token_request},
};

/// Renew a Secrets Manager access token against the Identity service.
///
/// Per ADR-089 this auth-side helper only performs the credential exchange and returns the new
/// token data `(access_token, refresh_token, expires_in)` to the caller. Persisting the renewed
/// token to the SM state file is the responsibility of the caller in `bitwarden-sm` (which owns
/// `state::set`), because `bitwarden-auth` cannot depend on `bitwarden-sm`.
pub async fn renew_sm_token(
    login_method: &SmLoginMethod,
    identity_config: bitwarden_api_api::Configuration,
) -> Result<(String, Option<String>, u64), LoginError> {
    let res = match login_method {
        SmLoginMethod::AccessToken { access_token, .. } => {
            send_access_token_request(
                &identity_config,
                access_token.access_token_id,
                &access_token.client_secret,
            )
            .await?
        }
    };

    match res {
        IdentityTokenResponse::Refreshed(r) => Ok((r.access_token, r.refresh_token, r.expires_in)),
        IdentityTokenResponse::Authenticated(r) => {
            Ok((r.access_token, r.refresh_token, r.expires_in))
        }
        IdentityTokenResponse::Payload(r) => Ok((r.access_token, r.refresh_token, r.expires_in)),
    }
}

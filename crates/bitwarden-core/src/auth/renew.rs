use super::login::LoginError;
use crate::{
    NotAuthenticatedError,
    auth::api::{request::ApiTokenRequest, response::IdentityTokenResponse},
    client::UserLoginMethod,
};

pub async fn renew_pm_token_sdk_managed(
    refresh_token: Option<String>,
    login_method: &UserLoginMethod,
    identity_config: bitwarden_api_api::Configuration,
) -> Result<(String, Option<String>, u64), LoginError> {
    let res = match login_method {
        UserLoginMethod::Username { client_id, .. } => {
            let refresh = refresh_token.ok_or(NotAuthenticatedError)?;

            crate::auth::api::request::RenewTokenRequest::new(refresh, client_id.to_owned())
                .send(&identity_config)
                .await?
        }
        UserLoginMethod::ApiKey {
            client_id,
            client_secret,
            ..
        } => {
            ApiTokenRequest::new(client_id, client_secret)
                .send(&identity_config)
                .await?
        }
    };

    match res {
        IdentityTokenResponse::Refreshed(r) => Ok((r.access_token, r.refresh_token, r.expires_in)),
        IdentityTokenResponse::Authenticated(r) => {
            Ok((r.access_token, r.refresh_token, r.expires_in))
        }
        _ => {
            // We should never get here
            Err(LoginError::InvalidResponse)
        }
    }
}

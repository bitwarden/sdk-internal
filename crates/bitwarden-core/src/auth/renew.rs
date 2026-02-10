use bitwarden_crypto::KeyStore;

use super::login::LoginError;
use crate::{
    NotAuthenticatedError,
    auth::api::{request::ApiTokenRequest, response::IdentityTokenResponse},
    client::UserLoginMethod,
    key_management::KeyIds,
};
#[cfg(feature = "secrets")]
use crate::{
    auth::api::request::AccessTokenRequest,
    client::ServiceAccountLoginMethod,
    key_management::SymmetricKeyId,
    secrets_manager::state::{self, ClientState},
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

#[cfg(feature = "secrets")]
pub async fn renew_sm_token_sdk_managed(
    login_method: &ServiceAccountLoginMethod,
    identity_config: bitwarden_api_api::Configuration,
    key_store: KeyStore<KeyIds>,
) -> Result<(String, Option<String>, u64), LoginError> {
    let res = match login_method {
        ServiceAccountLoginMethod::AccessToken {
            access_token,
            state_file,
            ..
        } => {
            let result =
                AccessTokenRequest::new(access_token.access_token_id, &access_token.client_secret)
                    .send(&identity_config)
                    .await?;

            if let (IdentityTokenResponse::Payload(r), Some(state_file)) = (&result, state_file) {
                let ctx = key_store.context();
                #[allow(deprecated)]
                if let Ok(enc_key) = ctx.dangerous_get_symmetric_key(SymmetricKeyId::User) {
                    let state = ClientState::new(r.access_token.clone(), enc_key.to_base64());
                    _ = state::set(state_file, access_token, state);
                }
            }

            result
        }
    };

    match res {
        IdentityTokenResponse::Refreshed(r) => Ok((r.access_token, r.refresh_token, r.expires_in)),
        IdentityTokenResponse::Authenticated(r) => {
            Ok((r.access_token, r.refresh_token, r.expires_in))
        }
        IdentityTokenResponse::Payload(r) => Ok((r.access_token, r.refresh_token, r.expires_in)),
        _ => {
            // We should never get here
            Err(LoginError::InvalidResponse)
        }
    }
}

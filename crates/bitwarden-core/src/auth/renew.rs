use std::sync::Arc;

use bitwarden_crypto::KeyStore;

use super::login::LoginError;
use crate::{
    NotAuthenticatedError,
    auth::api::{request::ApiTokenRequest, response::IdentityTokenResponse},
    client::{LoginMethod, UserLoginMethod},
    key_management::KeyIds,
};
#[cfg(feature = "secrets")]
use crate::{
    auth::api::request::AccessTokenRequest,
    client::ServiceAccountLoginMethod,
    key_management::SymmetricKeyId,
    secrets_manager::state::{self, ClientState},
};

pub async fn renew_token_sdk_managed(
    refresh_token: Option<String>,
    login_method: Arc<LoginMethod>,
    identity_config: bitwarden_api_api::Configuration,
    #[allow(unused)] key_store: KeyStore<KeyIds>,
) -> Result<(String, Option<String>, u64), LoginError> {
    let config = &identity_config;

    let res = match login_method.as_ref() {
        LoginMethod::User(u) => match u {
            UserLoginMethod::Username { client_id, .. } => {
                let refresh = refresh_token.ok_or(NotAuthenticatedError)?;

                crate::auth::api::request::RenewTokenRequest::new(refresh, client_id.to_owned())
                    .send(config)
                    .await?
            }
            UserLoginMethod::ApiKey {
                client_id,
                client_secret,
                ..
            } => {
                ApiTokenRequest::new(client_id, client_secret)
                    .send(config)
                    .await?
            }
        },
        #[cfg(feature = "secrets")]
        LoginMethod::ServiceAccount(s) => match s {
            ServiceAccountLoginMethod::AccessToken {
                access_token,
                state_file,
                ..
            } => {
                let result = AccessTokenRequest::new(
                    access_token.access_token_id,
                    &access_token.client_secret,
                )
                .send(config)
                .await?;

                if let (IdentityTokenResponse::Payload(r), Some(state_file)) = (&result, state_file)
                {
                    let ctx = key_store.context();
                    #[allow(deprecated)]
                    if let Ok(enc_key) = ctx.dangerous_get_symmetric_key(SymmetricKeyId::User) {
                        let state = ClientState::new(r.access_token.clone(), enc_key.to_base64());
                        _ = state::set(state_file, access_token, state);
                    }
                }

                result
            }
        },
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

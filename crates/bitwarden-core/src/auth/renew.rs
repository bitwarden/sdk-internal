use std::sync::Arc;

use chrono::Utc;

use super::login::LoginError;
use crate::{
    NotAuthenticatedError,
    auth::api::{request::ApiTokenRequest, response::IdentityTokenResponse},
    client::{
        LoginMethod, UserLoginMethod,
        internal::{ClientManagedTokens, InternalClient, SdkManagedTokens, Tokens},
    },
};
#[cfg(feature = "secrets")]
use crate::{
    auth::api::request::AccessTokenRequest,
    client::ServiceAccountLoginMethod,
    key_management::SymmetricKeyId,
    secrets_manager::state::{self, ClientState},
};

pub(crate) async fn renew_token(client: &InternalClient) -> Result<(), LoginError> {
    let tokens_guard = client
        .tokens
        .read()
        .expect("RwLock is not poisoned")
        .clone();

    match tokens_guard {
        Tokens::SdkManaged(tokens) => renew_token_sdk_managed(client, tokens).await,
        Tokens::ClientManaged(tokens) => renew_token_client_managed(client, tokens).await,
    }
}

async fn renew_token_client_managed(
    client: &InternalClient,
    tokens: Arc<dyn ClientManagedTokens>,
) -> Result<(), LoginError> {
    let token = tokens
        .get_access_token()
        .await
        .ok_or(NotAuthenticatedError)?;
    client.set_api_tokens_internal(token);
    Ok(())
}

async fn renew_token_sdk_managed(
    client: &InternalClient,
    tokens: SdkManagedTokens,
) -> Result<(), LoginError> {
    const TOKEN_RENEW_MARGIN_SECONDS: i64 = 5 * 60;

    let login_method = client
        .login_method
        .read()
        .expect("RwLock is not poisoned")
        .clone();

    if let (Some(expires), Some(login_method)) = (tokens.expires_on, login_method) {
        if Utc::now().timestamp() < expires - TOKEN_RENEW_MARGIN_SECONDS {
            return Ok(());
        }

        let config = client
            .__api_configurations
            .read()
            .expect("RwLock is not poisoned")
            .clone();

        let res = match login_method.as_ref() {
            LoginMethod::User(u) => match u {
                UserLoginMethod::Username { client_id, .. } => {
                    let refresh = tokens.refresh_token.ok_or(NotAuthenticatedError)?;

                    crate::auth::api::request::RenewTokenRequest::new(refresh, client_id.to_owned())
                        .send(&config)
                        .await?
                }
                UserLoginMethod::ApiKey {
                    client_id,
                    client_secret,
                    ..
                } => {
                    ApiTokenRequest::new(client_id, client_secret)
                        .send(&config)
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
                    .send(&config)
                    .await?;

                    if let (IdentityTokenResponse::Payload(r), Some(state_file)) =
                        (&result, state_file)
                    {
                        let key_store = client.get_key_store();
                        let ctx = key_store.context();
                        #[allow(deprecated)]
                        if let Ok(enc_key) = ctx.dangerous_get_symmetric_key(SymmetricKeyId::User) {
                            let state =
                                ClientState::new(r.access_token.clone(), enc_key.to_base64());
                            _ = state::set(state_file, access_token, state);
                        }
                    }

                    result
                }
            },
        };

        match res {
            IdentityTokenResponse::Refreshed(r) => {
                client.set_tokens(r.access_token, r.refresh_token, r.expires_in);
                return Ok(());
            }
            IdentityTokenResponse::Authenticated(r) => {
                client.set_tokens(r.access_token, r.refresh_token, r.expires_in);
                return Ok(());
            }
            IdentityTokenResponse::Payload(r) => {
                client.set_tokens(r.access_token, r.refresh_token, r.expires_in);
                return Ok(());
            }
            _ => {
                // We should never get here
                return Err(LoginError::InvalidResponse);
            }
        }
    }

    Err(NotAuthenticatedError)?
}

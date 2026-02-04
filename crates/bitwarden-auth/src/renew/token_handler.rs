//! Token handler implementation for Bitwarden authentication.

use std::sync::{Arc, RwLock};

use bitwarden_api_api::apis::AuthRequired;
use bitwarden_core::{
    NotAuthenticatedError,
    auth::{TokenHandler, login::LoginError},
    client::login_method::LoginMethod,
    key_management::KeyIds,
};
use bitwarden_crypto::KeyStore;
use chrono::Utc;

/// Token handler for Bitwarden authentication.
#[derive(Clone)]
pub struct AuthTokenHandler {
    inner: Arc<RwLock<PasswordManagerTokenHandlerInner>>,
}

impl Default for AuthTokenHandler {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(PasswordManagerTokenHandlerInner {
                access_token: None,
                expires_on: None,
                refresh_token: None,
                login_method: None,
                identity_config: None,
                key_store: None,
            })),
        }
    }
}

struct PasswordManagerTokenHandlerInner {
    access_token: Option<String>,
    expires_on: Option<i64>,

    refresh_token: Option<String>,

    // The following are passed as optional as they are filled in when instantiating the
    // middleware.

    // This type sucks, but we should be moving this into a Repository/setting soon.
    login_method: Option<Arc<RwLock<Option<Arc<LoginMethod>>>>>,
    identity_config: Option<bitwarden_api_api::Configuration>,
    key_store: Option<KeyStore<KeyIds>>,
}

impl TokenHandler for AuthTokenHandler {
    fn create_middleware(
        &self,
        login_method: Arc<RwLock<Option<Arc<LoginMethod>>>>,
        identity_config: bitwarden_api_api::Configuration,
        key_store: KeyStore<KeyIds>,
    ) -> Arc<dyn reqwest_middleware::Middleware> {
        {
            let mut inner = self.inner.write().expect("RwLock is not poisoned");
            inner.login_method = Some(login_method);
            inner.identity_config = Some(identity_config);
            inner.key_store = Some(key_store);
        }
        Arc::new(self.clone())
    }

    fn set_tokens(&self, token: String, refresh_token: Option<String>, expires_on: u64) {
        let mut inner = self.inner.write().expect("RwLock is not poisoned");
        inner.access_token = Some(token);
        inner.refresh_token = refresh_token;
        inner.expires_on = Some(expires_on as i64);
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl reqwest_middleware::Middleware for AuthTokenHandler {
    async fn handle(
        &self,
        mut req: reqwest::Request,
        ext: &mut http::Extensions,
        next: reqwest_middleware::Next<'_>,
    ) -> Result<reqwest::Response, reqwest_middleware::Error> {
        if ext.get::<AuthRequired>().is_some() {
            match self.get_token().await {
                Ok(Some(token)) => {
                    req.headers_mut().insert(
                        http::header::AUTHORIZATION,
                        format!("Bearer {}", token)
                            .parse()
                            .expect("Valid header value"),
                    );
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!("Failed to get auth token: {e}");
                }
            };
        }

        next.run(req, ext).await
    }
}

impl AuthTokenHandler {
    #[allow(clippy::unused_async)]
    async fn get_token(&self) -> Result<Option<String>, LoginError> {
        const TOKEN_RENEW_MARGIN_SECONDS: i64 = 5 * 60;

        let (refresh_token, login_method, identity_config, key_store) = {
            let inner = self.inner.read().expect("RwLock is not poisoned");
            if let Some(expires) = inner.expires_on
                && Utc::now().timestamp() < expires - TOKEN_RENEW_MARGIN_SECONDS
            {
                return Ok(inner.access_token.clone());
            }
            let refresh_token = inner.refresh_token.clone();
            let login_method = inner
                .login_method
                .as_ref()
                .and_then(|l| l.read().expect("RwLock is not poisoned").clone());
            let identity_config = inner.identity_config.clone();
            let key_store = inner.key_store.clone();
            (refresh_token, login_method, identity_config, key_store)
        };

        // Silence the warnings for now, will be used when we implement token renewal
        let _ = (
            refresh_token.as_ref(),
            login_method.as_ref(),
            identity_config.as_ref(),
            key_store.as_ref(),
        );

        /*if let (Some(login_method), Some(configuration)) = (login_method, identity_config) {
            let res = match login_method.as_ref() {
                LoginMethod::User(u) => match u {
                    UserLoginMethod::Username { client_id, .. } => {
                        let refresh = refresh_token.ok_or(NotAuthenticatedError)?;

                        bitwarden_core::auth::api::request::RenewTokenRequest::new(
                            refresh,
                            client_id.to_owned(),
                        )
                        .send(&configuration)
                        .await?
                    }
                    UserLoginMethod::ApiKey {
                        client_id,
                        client_secret,
                        ..
                    } => {
                        ApiTokenRequest::new(client_id, client_secret)
                            .send(&configuration)
                            .await?
                    }
                },
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
                        .send(&configuration)
                        .await?;

                        if let (
                            IdentityTokenResponse::Payload(r),
                            Some(state_file),
                            Some(key_store),
                        ) = (&result, state_file, key_store)
                        {
                            let ctx = key_store.context();
                            #[allow(deprecated)]
                            if let Ok(enc_key) =
                                ctx.dangerous_get_symmetric_key(SymmetricKeyId::User)
                            {
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
                    self.set_tokens(r.access_token.clone(), r.refresh_token, r.expires_in);
                    return Ok(Some(r.access_token));
                }
                IdentityTokenResponse::Authenticated(r) => {
                    self.set_tokens(r.access_token.clone(), r.refresh_token, r.expires_in);
                    return Ok(Some(r.access_token));
                }
                IdentityTokenResponse::Payload(r) => {
                    self.set_tokens(r.access_token.clone(), r.refresh_token, r.expires_in);
                    return Ok(Some(r.access_token));
                }
                _ => {
                    // We should never get here
                    return Err(LoginError::InvalidResponse);
                }
            }
        }*/

        Err(NotAuthenticatedError)?
    }
}

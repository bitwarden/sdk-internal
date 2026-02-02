use core::panic;
use std::sync::{Arc, RwLock};

use bitwarden_crypto::KeyStore;
use chrono::Utc;

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

/// Trait for handling token usage an renewal.
pub trait TokenHandler: 'static + Send + Sync {
    /// Create middleware that handles token attachment and renewal.
    /// This middleware should look for the presence of the [bitwarden_api_base::AuthRequired]
    /// extension to decide when to attach tokens. It's then free to attach tokens as it sees fit,
    /// including pausing and retrying requests to renew tokens.
    fn create_middleware(
        &self,
        login_method: Arc<RwLock<Option<Arc<LoginMethod>>>>,
        identity_config: bitwarden_api_base::Configuration,
        key_store: KeyStore<KeyIds>,
    ) -> Arc<dyn reqwest_middleware::Middleware>;

    /// This method is available only as a backwards compatibility measure until all the
    /// auth-related code is moved out of core. Once that is done, it is
    fn set_tokens(&self, token: String, refresh_token: Option<String>, expires_on: u64);
}

/// Access tokens managed by client applications, such as the web or mobile apps.
#[cfg_attr(feature = "uniffi", uniffi::export(with_foreign))]
#[async_trait::async_trait]
pub trait ClientManagedTokens: std::fmt::Debug + Send + Sync {
    /// Returns the access token, if available.
    async fn get_access_token(&self) -> Option<String>;
}

/// Token handler for client-managed tokens.
#[derive(Clone)]
pub struct ClientManagedTokenHandler {
    tokens: Arc<dyn ClientManagedTokens>,
}

impl ClientManagedTokenHandler {
    /// Create a new client-managed token handler.
    pub fn new(tokens: Arc<dyn ClientManagedTokens>) -> Arc<Self> {
        Arc::new(Self { tokens })
    }
}

impl TokenHandler for ClientManagedTokenHandler {
    fn create_middleware(
        &self,
        _login_method: Arc<RwLock<Option<Arc<LoginMethod>>>>,
        _identity_config: bitwarden_api_base::Configuration,
        _key_store: KeyStore<KeyIds>,
    ) -> Arc<dyn reqwest_middleware::Middleware> {
        Arc::new(self.clone())
    }

    fn set_tokens(&self, _token: String, _refresh_token: Option<String>, _expires_on: u64) {
        panic!("Client-managed tokens cannot be set by the SDK");
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl reqwest_middleware::Middleware for ClientManagedTokenHandler {
    async fn handle(
        &self,
        mut req: reqwest::Request,
        ext: &mut http::Extensions,
        next: reqwest_middleware::Next<'_>,
    ) -> Result<reqwest::Response, reqwest_middleware::Error> {
        if ext.get::<bitwarden_api_base::AuthRequired>().is_some() {
            if let Some(token) = self.tokens.get_access_token().await {
                req.headers_mut().insert(
                    http::header::AUTHORIZATION,
                    format!("Bearer {}", token)
                        .parse()
                        .expect("Valid header value"),
                );
            }
        }

        let resp = next.run(req, ext).await?;

        Ok(resp)
    }
}

// TODO: This needs to be moved to bitwarden-auth, but there are a couple of things in the way:
// - SM is initializing the client using core::Client::new(), which means this code needs to live in
//   core.
//    - Solution: Create a SecretsManagerClient that wraps core::Client and moves all auth-setup
//      code there. (Like we're doing with bitwarden-pm)
// - A lot of tests are using core::Client::new() directly.
//    - Solution: Expose a test_client function in bitwarden-test that does the correct setup for
//      the cases that need them. For other cases, we can offer a new_without_auth() function or
//      something.

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
    // These two fields are always written to, but they are not read
    // from the secrets manager SDK.
    access_token: Option<String>,
    expires_on: Option<i64>,

    refresh_token: Option<String>,

    login_method: Option<Arc<RwLock<Option<Arc<LoginMethod>>>>>,
    identity_config: Option<bitwarden_api_base::Configuration>,
    key_store: Option<KeyStore<KeyIds>>,
}

impl TokenHandler for AuthTokenHandler {
    fn create_middleware(
        &self,
        login_method: Arc<RwLock<Option<Arc<LoginMethod>>>>,
        identity_config: bitwarden_api_base::Configuration,
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
        if ext.get::<bitwarden_api_base::AuthRequired>().is_some() {
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

        if let (Some(login_method), Some(configuration)) = (login_method, identity_config) {
            let res = match login_method.as_ref() {
                LoginMethod::User(u) => match u {
                    UserLoginMethod::Username { client_id, .. } => {
                        let refresh = refresh_token.ok_or(NotAuthenticatedError)?;

                        crate::auth::api::request::RenewTokenRequest::new(
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
        }

        Err(NotAuthenticatedError)?
    }
}

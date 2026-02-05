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

#[derive(Clone)]
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
    fn initialize_middleware(
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

    fn set_tokens(&self, access_token: String, refresh_token: Option<String>, expires_on: u64) {
        let mut inner = self.inner.write().expect("RwLock is not poisoned");
        inner.access_token = Some(access_token);
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
                Ok(Some(token)) => set_token(&mut req, &token),
                Ok(None) => {
                    tracing::warn!("No token available for request requiring authentication");
                }
                Err(e) => {
                    tracing::warn!("Failed to get auth token: {e}");
                }
            };
        }

        next.run(req, ext).await
    }
}

fn set_token(req: &mut reqwest::Request, token: &str) {
    match format!("Bearer {}", token).parse() {
        Ok(header_value) => {
            req.headers_mut()
                .insert(http::header::AUTHORIZATION, header_value);
        }
        Err(e) => {
            tracing::warn!("Failed to parse auth token for header: {e}");
        }
    }
}

impl AuthTokenHandler {
    #[allow(clippy::unused_async)]
    async fn get_token(&self) -> Result<Option<String>, LoginError> {
        const TOKEN_RENEW_MARGIN_SECONDS: i64 = 5 * 60;

        // Validate the token, returning early if it's still valid.
        // If not, we clone the content of the RwLock to avoid holding it across an await point.
        let inner: PasswordManagerTokenHandlerInner = {
            let inner = self.inner.read().expect("RwLock is not poisoned");
            if let Some(expires) = inner.expires_on {
                if Utc::now().timestamp() < expires - TOKEN_RENEW_MARGIN_SECONDS {
                    return Ok(inner.access_token.clone());
                }
            }
            inner.clone()
        };

        let refresh_token = inner.refresh_token;

        // These should always be set by initialize_middleware before we get here, but we return an
        // error if not.
        let login_method = inner.login_method.ok_or(NotAuthenticatedError)?;
        let identity_config = inner.identity_config.ok_or(NotAuthenticatedError)?;
        let key_store = inner.key_store.ok_or(NotAuthenticatedError)?;

        let login_method = login_method
            .read()
            .expect("RwLock is not poisoned")
            .clone()
            .ok_or(NotAuthenticatedError)?;

        let (access_token, refresh_token, expires_on) =
            bitwarden_core::auth::renew::renew_token_sdk_managed(
                refresh_token,
                login_method,
                identity_config,
                key_store,
            )
            .await?;

        self.set_tokens(access_token.clone(), refresh_token, expires_on);
        Ok(Some(access_token))
    }
}

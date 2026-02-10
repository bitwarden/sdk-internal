use core::panic;
use std::sync::{Arc, RwLock};

use bitwarden_crypto::KeyStore;

use crate::{client::LoginMethod, key_management::KeyIds};

/// Trait for handling token usage an renewal.
pub trait TokenHandler: 'static + Send + Sync {
    /// Initialize middleware that handles token attachment and renewal.
    /// This middleware should look for the presence of the [bitwarden_api_base::AuthRequired]
    /// extension to decide when to attach tokens. It's then free to attach tokens as it sees fit,
    /// including pausing and retrying requests to renew tokens.
    fn initialize_middleware(
        &self,
        login_method: Arc<RwLock<Option<Arc<LoginMethod>>>>,
        identity_config: bitwarden_api_base::Configuration,
        key_store: KeyStore<KeyIds>,
    ) -> Arc<dyn reqwest_middleware::Middleware>;

    /// This method is available only as a backwards compatibility measure until all the
    /// auth-related code is moved out of core. Once that is done, setting tokens should be always
    /// done either during renewal (as part of the middleware) or during registration/login, in
    /// which case it would be up to the auth crate to internally set those tokens when initializing
    /// the client.
    fn set_tokens(&self, token: String, refresh_token: Option<String>, expires_in: u64);
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
    fn initialize_middleware(
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
        }

        let resp = next.run(req, ext).await?;

        Ok(resp)
    }
}

#[derive(Clone, Copy)]
pub struct NoopTokenHandler;

impl TokenHandler for NoopTokenHandler {
    fn initialize_middleware(
        &self,
        _login_method: Arc<RwLock<Option<Arc<LoginMethod>>>>,
        _identity_config: bitwarden_api_base::Configuration,
        _key_store: KeyStore<KeyIds>,
    ) -> Arc<dyn reqwest_middleware::Middleware> {
        Arc::new(*self)
    }

    fn set_tokens(&self, _token: String, _refresh_token: Option<String>, _expires_on: u64) {
        panic!("Cannot set tokens on NoopTokenHandler");
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl reqwest_middleware::Middleware for NoopTokenHandler {
    async fn handle(
        &self,
        req: reqwest::Request,
        ext: &mut http::Extensions,
        next: reqwest_middleware::Next<'_>,
    ) -> Result<reqwest::Response, reqwest_middleware::Error> {
        next.run(req, ext).await
    }
}

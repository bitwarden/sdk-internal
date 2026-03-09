//! Token handler implementation for Bitwarden Password Manager authentication.

use std::sync::{Arc, RwLock};

use bitwarden_core::{
    NotAuthenticatedError,
    auth::{TokenHandler, login::LoginError},
    client::login_method::LoginMethod,
    key_management::KeyIds,
};
use bitwarden_crypto::KeyStore;
use chrono::Utc;

use super::middleware::{MiddlewareExt, MiddlewareWrapper};
use crate::token_management::middleware::TOKEN_RENEW_MARGIN_SECONDS;

/// Token handler for Bitwarden authentication.
#[derive(Clone, Default)]
pub struct PasswordManagerTokenHandler {
    inner: Arc<RwLock<PasswordManagerTokenHandlerInner>>,
}

#[derive(Clone, Default)]
struct PasswordManagerTokenHandlerInner {
    access_token: Option<String>,
    expires_on: Option<i64>,

    refresh_token: Option<String>,

    // The following are passed as optional as they are filled in when instantiating the
    // middleware.
    login_method: Option<Arc<RwLock<Option<Arc<LoginMethod>>>>>,
    identity_config: Option<bitwarden_api_api::Configuration>,
}

impl TokenHandler for PasswordManagerTokenHandler {
    fn initialize_middleware(
        &self,
        login_method: Arc<RwLock<Option<Arc<LoginMethod>>>>,
        identity_config: bitwarden_api_api::Configuration,
        _key_store: KeyStore<KeyIds>,
    ) -> Arc<dyn reqwest_middleware::Middleware> {
        {
            let mut inner = self.inner.write().expect("RwLock is not poisoned");
            inner.login_method = Some(login_method);
            inner.identity_config = Some(identity_config);
        }
        Arc::new(MiddlewareWrapper(self.clone()))
    }

    fn set_tokens(&self, access_token: String, refresh_token: Option<String>, expires_in: u64) {
        let mut inner = self.inner.write().expect("RwLock is not poisoned");
        inner.access_token = Some(access_token);
        inner.refresh_token = refresh_token;
        inner.expires_on = Some(Utc::now().timestamp() + expires_in as i64);
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl MiddlewareExt for PasswordManagerTokenHandler {
    async fn get_token(&self) -> Result<Option<String>, LoginError> {
        // We're not holding on to a lock for the duration of the token renewal, so if multiple
        // requests come in at the same time when the token is expired, we may end up renewing the
        // token multiple times. This is not ideal, but it's the behavior of the previous
        // implementation. We should be able to introduce an async semaphore or something
        // similar to prevent this if it becomes an issue in practice.
        let inner = self.inner.read().expect("RwLock is not poisoned").clone();

        // Validate the token, returning early if it's still valid.
        if let Some(expires) = inner.expires_on
            && Utc::now().timestamp() < expires - TOKEN_RENEW_MARGIN_SECONDS
        {
            return Ok(inner.access_token.clone());
        }

        // These should always be set by initialize_middleware before we get here, but we return an
        // error if not.
        let login_method = inner.login_method.ok_or(NotAuthenticatedError)?;
        let identity_config = inner.identity_config.ok_or(NotAuthenticatedError)?;

        let login_method = login_method
            .read()
            .expect("RwLock is not poisoned")
            .clone()
            .ok_or(NotAuthenticatedError)?;

        let LoginMethod::User(user_login_method) = login_method.as_ref() else {
            return Err(NotAuthenticatedError.into());
        };

        let (access_token, refresh_token, expires_in) =
            bitwarden_core::auth::renew::renew_pm_token_sdk_managed(
                inner.refresh_token,
                user_login_method,
                identity_config,
            )
            .await?;

        self.set_tokens(access_token.clone(), refresh_token, expires_in);
        Ok(Some(access_token))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, RwLock};

    use bitwarden_core::{
        auth::TokenHandler,
        client::login_method::{LoginMethod, UserLoginMethod},
        key_management::KeyIds,
    };
    use bitwarden_crypto::{Kdf, KeyStore};
    use wiremock::MockServer;

    use super::*;
    use crate::token_management::test_utils::*;

    fn api_key_login_method() -> Arc<RwLock<Option<Arc<LoginMethod>>>> {
        Arc::new(RwLock::new(Some(Arc::new(LoginMethod::User(
            UserLoginMethod::ApiKey {
                client_id: "test-client".to_string(),
                client_secret: "test-secret".to_string(),
                email: "test@test.com".to_string(),
                kdf: Kdf::default_pbkdf2(),
            },
        )))))
    }

    #[tokio::test]
    async fn attaches_existing_token_when_not_expired() {
        let app_server = start_app_server().await;
        let identity_server = MockServer::start().await;

        let handler = PasswordManagerTokenHandler::default();
        handler.set_tokens(
            "original-token".to_string(),
            Some("refresh".to_string()),
            5000,
        );
        let client = build_client(handler.initialize_middleware(
            api_key_login_method(),
            identity_config(&identity_server.uri()),
            KeyStore::<KeyIds>::default(),
        ));

        let auth = send_auth_request(&client, &app_server).await;
        assert_eq!(auth.as_deref(), Some("Bearer original-token"));
        assert_eq!(identity_server.received_requests().await.unwrap().len(), 0);
        assert_eq!(app_server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn renews_expired_token() {
        let app_server = start_app_server().await;
        let identity_server = start_renewal_server("renewed-token").await;

        let handler = PasswordManagerTokenHandler::default();
        // expires_in=0 means the token is considered expired as it's less than the margin
        handler.set_tokens(
            "expired-token".to_string(),
            Some("old-refresh".to_string()),
            0,
        );

        let client = build_client(handler.initialize_middleware(
            api_key_login_method(),
            identity_config(&identity_server.uri()),
            KeyStore::<KeyIds>::default(),
        ));

        let auth = send_auth_request(&client, &app_server).await;
        assert_eq!(auth.as_deref(), Some("Bearer renewed-token"));
        assert_eq!(identity_server.received_requests().await.unwrap().len(), 1);
        assert_eq!(app_server.received_requests().await.unwrap().len(), 1);
    }
}

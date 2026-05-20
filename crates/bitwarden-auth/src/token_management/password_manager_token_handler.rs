//! Token handler implementation for Bitwarden Password Manager authentication.

use std::sync::{Arc, RwLock};

use bitwarden_core::{
    NotAuthenticatedError,
    auth::{TokenHandler, login::LoginError},
    client::{
        login_method::UserLoginMethod,
        persisted_state::{AUTHENTICATION_TOKENS, AuthenticationTokens, USER_LOGIN_METHOD},
    },
    key_management::KeySlotIds,
};
use bitwarden_crypto::KeyStore;
use bitwarden_state::{registry::StateRegistry, settings::Setting};
use chrono::Utc;

use super::middleware::{MiddlewareExt, MiddlewareWrapper};

/// Token handler for Bitwarden authentication.
#[derive(Clone, Default)]
pub struct PasswordManagerTokenHandler {
    inner: Arc<RwLock<PasswordManagerTokenHandlerInner>>,
}

#[derive(Clone, Default)]
struct PasswordManagerTokenHandlerInner {
    // Filled in by initialize_middleware.
    tokens: Option<Setting<AuthenticationTokens>>,
    login_method: Option<Setting<UserLoginMethod>>,
    identity_config: Option<bitwarden_api_api::Configuration>,
}

#[async_trait::async_trait]
impl TokenHandler for PasswordManagerTokenHandler {
    fn initialize_middleware(
        &self,
        state_registry: &StateRegistry,
        identity_config: bitwarden_api_api::Configuration,
        _key_store: KeyStore<KeySlotIds>,
    ) -> Arc<dyn reqwest_middleware::Middleware> {
        {
            let mut inner = self.inner.write().expect("RwLock is not poisoned");
            inner.tokens = state_registry.setting(AUTHENTICATION_TOKENS).ok();
            inner.login_method = state_registry.setting(USER_LOGIN_METHOD).ok();
            inner.identity_config = Some(identity_config);
        }
        Arc::new(MiddlewareWrapper::new(self.clone()))
    }

    async fn set_tokens(
        &self,
        access_token: String,
        refresh_token: Option<String>,
        expires_in: u64,
    ) {
        let tokens = self
            .inner
            .read()
            .expect("RwLock is not poisoned")
            .tokens
            .clone();

        if let Some(tokens) = tokens {
            tokens
                .update(AuthenticationTokens {
                    access_token,
                    refresh_token,
                    expires_on: Utc::now().timestamp() + expires_in as i64,
                })
                .await
                .ok();
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl MiddlewareExt for PasswordManagerTokenHandler {
    async fn current_token(&self) -> Option<(String, i64)> {
        let inner = self.inner.read().expect("RwLock is not poisoned").clone();
        let tokens = inner.tokens?.get().await.ok().flatten()?;
        Some((tokens.access_token, tokens.expires_on))
    }

    async fn renew_token(&mut self) -> Result<Option<String>, LoginError> {
        let inner = self.inner.read().expect("RwLock is not poisoned").clone();

        let tokens = inner
            .tokens
            .ok_or(NotAuthenticatedError)?
            .get()
            .await
            .ok()
            .flatten()
            .ok_or(NotAuthenticatedError)?;

        let login_method = inner.login_method.ok_or(NotAuthenticatedError)?;
        let identity_config = inner.identity_config.ok_or(NotAuthenticatedError)?;

        let login_method = login_method
            .get()
            .await
            .ok()
            .flatten()
            .ok_or(NotAuthenticatedError)?;

        let (access_token, refresh_token, expires_in) =
            bitwarden_core::auth::renew::renew_pm_token_sdk_managed(
                tokens.refresh_token,
                &login_method,
                identity_config,
            )
            .await?;

        self.set_tokens(access_token.clone(), refresh_token, expires_in)
            .await;
        Ok(Some(access_token))
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::apis::AuthRequired;
    use bitwarden_core::client::{
        login_method::UserLoginMethod,
        persisted_state::{AuthenticationTokens, USER_LOGIN_METHOD},
    };
    use bitwarden_crypto::Kdf;
    use bitwarden_state::registry::StateRegistry;
    use wiremock::MockServer;

    use super::*;
    use crate::token_management::test_utils::*;

    async fn registry_with_api_key_login() -> StateRegistry {
        let registry = StateRegistry::new_with_memory_db();
        registry
            .setting(USER_LOGIN_METHOD)
            .unwrap()
            .update(UserLoginMethod::ApiKey {
                client_id: "test-client".to_string(),
                client_secret: "test-secret".to_string(),
                email: "test@test.com".to_string(),
                kdf: Kdf::default_pbkdf2(),
            })
            .await
            .unwrap();
        registry
    }

    async fn seed_tokens(
        registry: &StateRegistry,
        access_token: &str,
        refresh_token: Option<&str>,
        expires_in: i64,
    ) {
        registry
            .setting(AUTHENTICATION_TOKENS)
            .unwrap()
            .update(AuthenticationTokens {
                access_token: access_token.to_string(),
                refresh_token: refresh_token.map(str::to_string),
                expires_on: Utc::now().timestamp() + expires_in,
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn attaches_existing_token_when_not_expired() {
        let app_server = start_app_server().await;
        let identity_server = MockServer::start().await;

        let registry = registry_with_api_key_login().await;
        seed_tokens(&registry, "original-token", Some("refresh"), 5000).await;

        let handler = PasswordManagerTokenHandler::default();
        let client = build_client(&handler, &registry, &identity_server);

        let auth = send_auth_request(&client, &app_server).await;
        assert_eq!(auth.as_deref(), Some("Bearer original-token"));
        assert_eq!(identity_server.received_requests().await.unwrap().len(), 0);
        assert_eq!(app_server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn renews_expired_token() {
        let app_server = start_app_server().await;
        let identity_server = start_renewal_server("renewed-token").await;

        let registry = registry_with_api_key_login().await;
        // expires_in=0 puts the token inside the renewal margin.
        seed_tokens(&registry, "expired-token", Some("old-refresh"), 0).await;

        let handler = PasswordManagerTokenHandler::default();
        let client = build_client(&handler, &registry, &identity_server);

        let auth = send_auth_request(&client, &app_server).await;
        assert_eq!(auth.as_deref(), Some("Bearer renewed-token"));
        assert_eq!(identity_server.received_requests().await.unwrap().len(), 1);
        assert_eq!(app_server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn retries_with_renewed_token_on_401() {
        let app_server = start_app_server_rejecting("stale-token").await;
        let identity_server = start_renewal_server("renewed-token").await;

        let registry = registry_with_api_key_login().await;
        // Locally-valid token forces renewal through the 401 retry path.
        seed_tokens(&registry, "stale-token", Some("refresh"), 5000).await;

        let handler = PasswordManagerTokenHandler::default();
        let client = build_client(&handler, &registry, &identity_server);

        let response = client
            .get(format!("{}/test", app_server.uri()))
            .with_extension(AuthRequired::Bearer)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);

        let requests = app_server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0].headers.get("Authorization").unwrap(),
            "Bearer stale-token"
        );
        assert_eq!(
            requests[1].headers.get("Authorization").unwrap(),
            "Bearer renewed-token"
        );
        assert_eq!(identity_server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn refreshes_on_retry_when_initial_token_unavailable() {
        // First identity call fails, so the initial request goes out unauthenticated and the
        // forced renewal on retry produces a valid token.
        let app_server = start_app_server_accepting("renewed-token").await;
        let identity_server = start_renewal_server_failing_then_succeeding("renewed-token").await;

        let registry = registry_with_api_key_login().await;
        seed_tokens(&registry, "stale-token", Some("refresh"), 0).await;

        let handler = PasswordManagerTokenHandler::default();
        let client = build_client(&handler, &registry, &identity_server);

        let response = client
            .get(format!("{}/test", app_server.uri()))
            .with_extension(AuthRequired::Bearer)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);

        let requests = app_server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].headers.get("Authorization").is_none());
        assert_eq!(
            requests[1].headers.get("Authorization").unwrap(),
            "Bearer renewed-token"
        );
        assert_eq!(identity_server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn concurrent_401s_trigger_a_single_renewal() {
        // Locally-valid tokens, so renewal only happens via the 401 retry path. Coalescing should
        // collapse the five retries into a single identity-server call.
        let app_server = start_app_server_rejecting("stale-token").await;
        let identity_server =
            start_renewal_server_with_delay("renewed-token", std::time::Duration::from_millis(100))
                .await;

        let registry = registry_with_api_key_login().await;
        seed_tokens(&registry, "stale-token", Some("refresh"), 5000).await;

        let handler = PasswordManagerTokenHandler::default();
        let client = build_client(&handler, &registry, &identity_server);

        send_concurrent_auth_requests(&client, &app_server, 5).await;

        assert_eq!(identity_server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn concurrent_requests_trigger_a_single_renewal() {
        let app_server = start_app_server().await;
        // Renewal delay so that concurrent renewals would overlap if not serialized.
        let identity_server =
            start_renewal_server_with_delay("renewed-token", std::time::Duration::from_millis(100))
                .await;

        let registry = registry_with_api_key_login().await;
        seed_tokens(&registry, "expired-token", Some("refresh"), 0).await;

        let handler = PasswordManagerTokenHandler::default();
        let client = build_client(&handler, &registry, &identity_server);

        send_concurrent_auth_requests(&client, &app_server, 5).await;

        assert_eq!(identity_server.received_requests().await.unwrap().len(), 1);
        let app_requests = app_server.received_requests().await.unwrap();
        assert_eq!(app_requests.len(), 5);
        for req in app_requests {
            assert_eq!(
                req.headers.get("Authorization").unwrap(),
                "Bearer renewed-token"
            );
        }
    }
}

//! Token handler implementation for Bitwarden Secrets Manager authentication.

use std::sync::{Arc, RwLock};

use bitwarden_core::{
    NotAuthenticatedError, OrganizationId,
    auth::{TokenHandler, login::LoginError},
    client::login_method::ServiceAccountLoginMethod,
    key_management::KeySlotIds,
};
use bitwarden_crypto::KeyStore;
use bitwarden_state::registry::StateRegistry;
use chrono::Utc;

use super::middleware::{MiddlewareExt, MiddlewareWrapper};

/// Token handler for Bitwarden authentication.
#[derive(Clone, Default)]
pub struct SecretsManagerTokenHandler {
    inner: Arc<RwLock<SecretsManagerTokenHandlerInner>>,
}

#[derive(Clone, Default)]
struct SecretsManagerTokenHandlerInner {
    access_token: Option<String>,
    expires_on: Option<i64>,

    // Filled in by initialize_middleware / set_sm_login_method.
    login_method: Option<Arc<ServiceAccountLoginMethod>>,
    identity_config: Option<bitwarden_api_api::Configuration>,
    key_store: Option<KeyStore<KeySlotIds>>,
}

#[async_trait::async_trait]
impl TokenHandler for SecretsManagerTokenHandler {
    fn initialize_middleware(
        &self,
        _state_registry: &StateRegistry,
        identity_config: bitwarden_api_api::Configuration,
        key_store: KeyStore<KeySlotIds>,
    ) -> Arc<dyn reqwest_middleware::Middleware> {
        {
            let mut inner = self.inner.write().expect("RwLock is not poisoned");
            inner.identity_config = Some(identity_config);
            inner.key_store = Some(key_store);
        }
        Arc::new(MiddlewareWrapper::new(self.clone()))
    }

    async fn set_tokens(
        &self,
        access_token: String,
        _refresh_token: Option<String>,
        expires_in: u64,
    ) {
        let mut inner = self.inner.write().expect("RwLock is not poisoned");
        inner.access_token = Some(access_token);
        inner.expires_on = Some(Utc::now().timestamp() + expires_in as i64);
    }

    async fn set_sm_login_method(&self, login_method: ServiceAccountLoginMethod) {
        let mut inner = self.inner.write().expect("RwLock is not poisoned");
        inner.login_method = Some(Arc::new(login_method));
    }
}

impl SecretsManagerTokenHandler {
    /// Get the organization ID associated with the current access token, if available.
    pub fn get_access_token_organization(&self) -> Option<OrganizationId> {
        let inner = self.inner.read().ok()?;
        match inner.login_method.as_deref()? {
            ServiceAccountLoginMethod::AccessToken {
                organization_id, ..
            } => Some(*organization_id),
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl MiddlewareExt for SecretsManagerTokenHandler {
    async fn current_token(&self) -> Option<(String, i64)> {
        let inner = self.inner.read().expect("RwLock is not poisoned").clone();
        Some((inner.access_token?, inner.expires_on?))
    }

    async fn renew_token(&mut self) -> Result<Option<String>, LoginError> {
        let inner = self.inner.read().expect("RwLock is not poisoned").clone();

        let login_method = inner.login_method.ok_or(NotAuthenticatedError)?;
        let identity_config = inner.identity_config.ok_or(NotAuthenticatedError)?;
        let key_store = inner.key_store.ok_or(NotAuthenticatedError)?;

        let (access_token, refresh_token, expires_in) =
            bitwarden_core::auth::renew::renew_sm_token_sdk_managed(
                login_method.as_ref(),
                identity_config,
                key_store,
            )
            .await?;

        self.set_tokens(access_token.clone(), refresh_token, expires_in)
            .await;
        Ok(Some(access_token))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitwarden_api_api::apis::AuthRequired;
    use bitwarden_core::{auth::AccessToken, client::login_method::ServiceAccountLoginMethod};
    use bitwarden_state::registry::StateRegistry;
    use wiremock::MockServer;

    use super::*;
    use crate::token_management::test_utils::*;

    fn service_account_login_method() -> ServiceAccountLoginMethod {
        let access_token = AccessToken::from_str(
            "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==",
        )
        .unwrap();

        ServiceAccountLoginMethod::AccessToken {
            access_token,
            organization_id: "00000000-0000-0000-0000-000000000001".parse().unwrap(),
            state_file: None,
        }
    }

    #[tokio::test]
    async fn attaches_existing_token_when_not_expired() {
        let app_server = start_app_server().await;
        let identity_server = MockServer::start().await;

        let handler = SecretsManagerTokenHandler::default();
        handler
            .set_sm_login_method(service_account_login_method())
            .await;
        handler
            .set_tokens("original-token".to_string(), None, 3600)
            .await;

        let registry = StateRegistry::new_with_memory_db();
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

        let handler = SecretsManagerTokenHandler::default();
        handler
            .set_sm_login_method(service_account_login_method())
            .await;
        // expires_in=0 puts the token inside the renewal margin.
        handler
            .set_tokens("expired-token".to_string(), None, 0)
            .await;

        let registry = StateRegistry::new_with_memory_db();
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

        let handler = SecretsManagerTokenHandler::default();
        handler
            .set_sm_login_method(service_account_login_method())
            .await;
        // Locally-valid token forces renewal through the 401 retry path.
        handler
            .set_tokens("stale-token".to_string(), None, 3600)
            .await;

        let registry = StateRegistry::new_with_memory_db();
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

        let handler = SecretsManagerTokenHandler::default();
        handler
            .set_sm_login_method(service_account_login_method())
            .await;

        let registry = StateRegistry::new_with_memory_db();
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

        let handler = SecretsManagerTokenHandler::default();
        handler
            .set_sm_login_method(service_account_login_method())
            .await;
        handler
            .set_tokens("stale-token".to_string(), None, 3600)
            .await;

        let registry = StateRegistry::new_with_memory_db();
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

        let handler = SecretsManagerTokenHandler::default();
        handler
            .set_sm_login_method(service_account_login_method())
            .await;
        handler
            .set_tokens("expired-token".to_string(), None, 0)
            .await;

        let registry = StateRegistry::new_with_memory_db();
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

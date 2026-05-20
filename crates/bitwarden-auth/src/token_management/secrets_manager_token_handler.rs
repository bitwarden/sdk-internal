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
use crate::token_management::middleware::TOKEN_RENEW_MARGIN_SECONDS;

/// Token handler for Bitwarden authentication.
#[derive(Clone, Default)]
pub struct SecretsManagerTokenHandler {
    inner: Arc<RwLock<SecretsManagerTokenHandlerInner>>,
}

#[derive(Clone, Default)]
struct SecretsManagerTokenHandlerInner {
    access_token: Option<String>,
    expires_on: Option<i64>,

    // The following are passed as optional as they are filled in when instantiating the
    // middleware.
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
        Arc::new(MiddlewareWrapper(self.clone()))
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
    async fn get_token(&self, force: bool) -> Result<Option<String>, LoginError> {
        // We're not holding on to a lock for the duration of the token renewal, so if multiple
        // requests come in at the same time when the token is expired, we may end up renewing the
        // token multiple times. This is not ideal, but it's the behavior of the previous
        // implementation. We should be able to introduce an async semaphore or something
        // similar to prevent this if it becomes an issue in practice.
        let inner = self.inner.read().expect("RwLock is not poisoned").clone();

        // Validate the token, returning early if it's still valid.
        if !force
            && let Some(expires) = inner.expires_on
            && Utc::now().timestamp() < expires - TOKEN_RENEW_MARGIN_SECONDS
        {
            return Ok(inner.access_token.clone());
        }

        // These should always be set by initialize_middleware / set_sm_login_method before we get
        // here, but we return an error if not.
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
    use bitwarden_core::{
        auth::{AccessToken, TokenHandler},
        client::login_method::ServiceAccountLoginMethod,
        key_management::KeySlotIds,
    };
    use bitwarden_crypto::KeyStore;
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
        let client = build_client(handler.initialize_middleware(
            &registry,
            identity_config(&identity_server.uri()),
            KeyStore::<KeySlotIds>::default(),
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

        let handler = SecretsManagerTokenHandler::default();
        handler
            .set_sm_login_method(service_account_login_method())
            .await;
        // expires_in=0 means the token is immediately considered expired
        handler
            .set_tokens("expired-token".to_string(), None, 0)
            .await;

        let registry = StateRegistry::new_with_memory_db();
        let client = build_client(handler.initialize_middleware(
            &registry,
            identity_config(&identity_server.uri()),
            KeyStore::<KeySlotIds>::default(),
        ));

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
        // Token is locally valid; the only renewal path is the 401 retry.
        handler
            .set_tokens("stale-token".to_string(), None, 3600)
            .await;

        let registry = StateRegistry::new_with_memory_db();
        let client = build_client(handler.initialize_middleware(
            &registry,
            identity_config(&identity_server.uri()),
            KeyStore::<KeySlotIds>::default(),
        ));

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
        // App server rejects unauthenticated requests with 401 but accepts the renewed token.
        let app_server = MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::header(
            "Authorization",
            "Bearer renewed-token",
        ))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .mount(&app_server)
        .await;
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(wiremock::ResponseTemplate::new(401))
            .mount(&app_server)
            .await;

        // Identity server fails the first renewal and succeeds on the second, so the initial
        // get_token call returns no token, but the forced refresh on retry produces one.
        let identity_server = MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/connect/token"))
            .respond_with(wiremock::ResponseTemplate::new(500))
            .up_to_n_times(1)
            .mount(&identity_server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/connect/token"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "renewed-token",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                    "scope": "api"
                })),
            )
            .mount(&identity_server)
            .await;

        let handler = SecretsManagerTokenHandler::default();
        handler
            .set_sm_login_method(service_account_login_method())
            .await;
        // No tokens seeded -> get_token always reaches the renewal path.

        let registry = StateRegistry::new_with_memory_db();
        let client = build_client(handler.initialize_middleware(
            &registry,
            identity_config(&identity_server.uri()),
            KeyStore::<KeySlotIds>::default(),
        ));

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
    async fn does_not_retry_when_no_auth_extension() {
        let server = MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(wiremock::ResponseTemplate::new(401))
            .mount(&server)
            .await;

        // Request is sent without the AuthRequired extension, so the middleware never asks
        // for a token and must not retry on 401.
        let handler = SecretsManagerTokenHandler::default();

        let registry = StateRegistry::new_with_memory_db();
        let client = build_client(handler.initialize_middleware(
            &registry,
            identity_config(&server.uri()),
            KeyStore::<KeySlotIds>::default(),
        ));

        let response = client
            .get(format!("{}/test", server.uri()))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 401);

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].headers.get("Authorization").is_none());
    }
}

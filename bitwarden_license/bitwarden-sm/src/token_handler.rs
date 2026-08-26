//! Token handler implementation for Bitwarden Secrets Manager authentication.
//!
//! Per ADR-089 the handler lives in `bitwarden-sm` (not `bitwarden-auth`) so that `renew_token`
//! can persist the renewed token to the SM state file via [`state::set`], which is owned by this
//! crate. The credential exchange itself is delegated to the auth-side helper
//! [`bitwarden_auth::token_management::renew_sm_token`].

use std::sync::{Arc, RwLock};

use bitwarden_auth::{
    service_account_login_method::ServiceAccountLoginMethod,
    token_management::{MiddlewareExt, MiddlewareWrapper, renew_sm_token},
};
use bitwarden_core::{
    NotAuthenticatedError, OrganizationId,
    auth::{TokenHandler, login::LoginError},
    key_management::{KeySlotIds, SymmetricKeySlotId},
};
use bitwarden_crypto::KeyStore;
use bitwarden_state::registry::StateRegistry;
use chrono::Utc;

use crate::state::{self, ClientState};

/// Token handler for Bitwarden Secrets Manager authentication.
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
}

impl SecretsManagerTokenHandler {
    /// Store the Secrets Manager login method on the handler.
    ///
    /// SM tokens are not persisted, so the login method lives in-memory on the handler.
    pub fn set_sm_login_method(&self, login_method: ServiceAccountLoginMethod) {
        let mut inner = self.inner.write().expect("RwLock is not poisoned");
        inner.login_method = Some(Arc::new(login_method));
    }

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

        let (access_token, refresh_token, expires_in) =
            renew_sm_token(login_method.as_ref(), identity_config).await?;

        // Persist the renewed token to the SM state file, preserving the pre-extraction behavior:
        // when the login method carries a state file and the User key slot is populated, rewrite
        // the encrypted state file so a later cold start can reuse the token without a fresh login.
        let ServiceAccountLoginMethod::AccessToken {
            access_token: sm_access_token,
            state_file,
            ..
        } = login_method.as_ref();

        if let (Some(state_file), Some(key_store)) = (state_file, inner.key_store.as_ref()) {
            let ctx = key_store.context();
            #[allow(deprecated)]
            if let Ok(enc_key) = ctx.dangerous_get_symmetric_key(SymmetricKeySlotId::User) {
                let client_state = ClientState::new(access_token.clone(), enc_key.to_base64());
                let _ = state::set(state_file, sm_access_token, client_state);
            }
        }

        self.set_tokens(access_token.clone(), refresh_token, expires_in)
            .await;
        Ok(Some(access_token))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitwarden_api_api::apis::AuthRequired;
    use bitwarden_auth::AccessToken;
    use bitwarden_state::registry::StateRegistry;
    use wiremock::MockServer;

    use super::*;
    use crate::test_utils::*;

    fn service_account_login_method() -> ServiceAccountLoginMethod {
        service_account_login_method_with_state(None)
    }

    fn service_account_login_method_with_state(
        state_file: Option<std::path::PathBuf>,
    ) -> ServiceAccountLoginMethod {
        let access_token = test_access_token();

        ServiceAccountLoginMethod::AccessToken {
            access_token,
            organization_id: "00000000-0000-0000-0000-000000000001".parse().unwrap(),
            state_file,
        }
    }

    fn test_access_token() -> AccessToken {
        AccessToken::from_str(
            "0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==",
        )
        .unwrap()
    }

    #[tokio::test]
    async fn attaches_existing_token_when_not_expired() {
        let app_server = start_app_server().await;
        let identity_server = MockServer::start().await;

        let handler = SecretsManagerTokenHandler::default();
        handler.set_sm_login_method(service_account_login_method());
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
        handler.set_sm_login_method(service_account_login_method());
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

    /// Regression (PM-25937): the SM state file must be rewritten on token renewal when the login
    /// method carries a `state_file` and the User key slot is populated. This behavior was silently
    /// dropped when the handler was first extracted to `bitwarden-auth` (which cannot call
    /// `state::set`). The handler now lives in `bitwarden-sm` per ADR-089 and restores the write.
    #[tokio::test]
    async fn renewal_rewrites_state_file() {
        let app_server = start_app_server().await;
        let identity_server = start_renewal_server("renewed-token").await;

        let state_file = std::env::temp_dir().join(format!("bwsm-state-{}", uuid::Uuid::new_v4()));

        let access_token = test_access_token();
        // Reuse the access token's derived key as the User-slot key to exercise the write path.
        let user_key = access_token.encryption_key.clone();
        // The state file is encrypted with the login method's access token encryption key.
        let sm_access_token = test_access_token();

        let handler = SecretsManagerTokenHandler::default();
        handler.set_sm_login_method(service_account_login_method_with_state(Some(
            state_file.clone(),
        )));
        // expires_in=0 puts the token inside the renewal margin so a renewal is forced.
        handler
            .set_tokens("expired-token".to_string(), None, 0)
            .await;

        // Seed the User key slot so the state-file write path has a key to persist.
        let key_store = KeyStore::<KeySlotIds>::default();
        #[allow(deprecated)]
        key_store
            .context_mut()
            .set_symmetric_key(SymmetricKeySlotId::User, user_key)
            .unwrap();

        let registry = StateRegistry::new_with_memory_db();
        let middleware = handler.initialize_middleware(
            &registry,
            bitwarden_api_api::Configuration::new(identity_server.uri()),
            key_store,
        );
        let client = reqwest_middleware::ClientBuilder::new(bitwarden_api_api::new_http_client())
            .with_arc(middleware)
            .build();

        let auth = send_auth_request(&client, &app_server).await;
        assert_eq!(auth.as_deref(), Some("Bearer renewed-token"));

        assert!(
            state_file.exists(),
            "state file was not rewritten on token renewal"
        );

        // The persisted state must decrypt to the renewed token.
        let persisted = state::get(&state_file, &sm_access_token)
            .expect("state file should decrypt with the SM access token key");
        assert_eq!(persisted.token, "renewed-token");

        let _ = std::fs::remove_file(&state_file);
    }

    #[tokio::test]
    async fn retries_with_renewed_token_on_401() {
        let app_server = start_app_server_rejecting("stale-token").await;
        let identity_server = start_renewal_server("renewed-token").await;

        let handler = SecretsManagerTokenHandler::default();
        handler.set_sm_login_method(service_account_login_method());
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
        handler.set_sm_login_method(service_account_login_method());

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
        handler.set_sm_login_method(service_account_login_method());
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
        handler.set_sm_login_method(service_account_login_method());
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

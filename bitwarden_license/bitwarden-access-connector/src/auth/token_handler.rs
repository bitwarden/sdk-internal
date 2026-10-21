//! Bridges the access connector's session into `bitwarden_core::Client`.
//!
//! The connector authenticates through its own [`IdentityClient`][crate::auth::identity] (core's
//! access-token request is Secrets-Manager-shaped), so this handler owns no token state. It hands
//! core the auth middleware and gives that middleware somewhere to find the session.
//!
//! Like `SecretsManagerTokenHandler`, it is built empty: [`TokenHandler::initialize_middleware`]
//! back-populates the key store during client construction, then
//! [`AccessConnectorTokenHandler::set_session`] fills in the session, which needs that store.

use std::sync::{Arc, RwLock};

use bitwarden_core::{auth::TokenHandler, key_management::KeySlotIds};
use bitwarden_crypto::KeyStore;
use bitwarden_state::registry::StateRegistry;

use crate::{api::AccessConnectorAuthMiddleware, auth::session::SessionManager};

/// Token handler for the PAM access connector.
#[derive(Clone, Default)]
pub(crate) struct AccessConnectorTokenHandler {
    inner: Arc<RwLock<Inner>>,
}

#[derive(Default)]
struct Inner {
    /// Set by [`TokenHandler::initialize_middleware`] during client construction.
    key_store: Option<KeyStore<KeySlotIds>>,
    /// Set by [`AccessConnectorTokenHandler::set_session`] once the session has authenticated.
    session: Option<Arc<SessionManager>>,
}

impl AccessConnectorTokenHandler {
    /// The key store core created. Clones of a [`KeyStore`] share their keys, so clearing it on
    /// revocation reaches core too.
    pub(crate) fn key_store(&self) -> Option<KeyStore<KeySlotIds>> {
        self.inner
            .read()
            .expect("RwLock is not poisoned")
            .key_store
            .clone()
    }

    /// Requests made before this lands cannot be authenticated.
    pub(crate) fn set_session(&self, session: Arc<SessionManager>) {
        self.inner
            .write()
            .expect("RwLock is not poisoned")
            .session
            .replace(session);
    }

    pub(crate) fn session(&self) -> Option<Arc<SessionManager>> {
        self.inner
            .read()
            .expect("RwLock is not poisoned")
            .session
            .clone()
    }
}

#[async_trait::async_trait]
impl TokenHandler for AccessConnectorTokenHandler {
    fn initialize_middleware(
        &self,
        _state_registry: &StateRegistry,
        _identity_config: bitwarden_api_base::Configuration,
        key_store: KeyStore<KeySlotIds>,
    ) -> Arc<dyn reqwest_middleware::Middleware> {
        self.inner
            .write()
            .expect("RwLock is not poisoned")
            .key_store
            .replace(key_store);

        Arc::new(AccessConnectorAuthMiddleware::new(self.clone()))
    }

    /// No-op: [`SessionManager`] owns the bearer and its renewal.
    async fn set_tokens(&self, _token: String, _refresh_token: Option<String>, _expires_in: u64) {}
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::apis::AuthRequired;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::*;

    /// Startup reads the key store back out of the handler, so `build` must have populated it.
    #[test]
    fn initialize_middleware_back_populates_the_key_store() {
        let handler = AccessConnectorTokenHandler::default();
        assert!(handler.key_store().is_none());

        let _client = bitwarden_core::ClientBuilder::new()
            .with_token_handler(Arc::new(handler.clone()))
            .build();

        assert!(
            handler.key_store().is_some(),
            "ClientBuilder::build must leave the key store available"
        );
    }

    /// The handler's key store is the client's, not a copy: clearing one empties the other.
    #[test]
    fn the_key_store_is_shared_with_the_client() {
        use bitwarden_core::key_management::SymmetricKeySlotId;
        use bitwarden_crypto::{SymmetricCryptoKey, SymmetricKeyAlgorithm};

        let handler = AccessConnectorTokenHandler::default();
        let client = bitwarden_core::ClientBuilder::new()
            .with_token_handler(Arc::new(handler.clone()))
            .build();

        let slot = SymmetricKeySlotId::Organization(
            "3f1a5c4e-7b2d-4f8a-9c6e-1d2b3a4c5d6e"
                .parse()
                .expect("uuid"),
        );
        let store = handler.key_store().expect("key store");
        #[allow(deprecated)]
        store
            .context_mut()
            .set_symmetric_key(
                slot,
                SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
            )
            .expect("set key");

        assert!(
            client
                .internal
                .get_key_store()
                .context()
                .has_symmetric_key(slot)
        );

        store.clear();

        assert!(
            !client
                .internal
                .get_key_store()
                .context()
                .has_symmetric_key(slot),
            "clearing the session's store must empty the client's"
        );
    }

    /// An authenticated request before a session is installed must fail, not go out bearer-less.
    #[tokio::test]
    async fn an_authenticated_request_without_a_session_fails_and_is_not_sent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/test"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let handler = AccessConnectorTokenHandler::default();
        let client = reqwest_middleware::ClientBuilder::new(
            bitwarden_api_base::new_http_client_builder()
                .build()
                .expect("http client"),
        )
        .with(AccessConnectorAuthMiddleware::new(handler))
        .build();

        client
            .get(format!("{}/test", server.uri()))
            .with_extension(AuthRequired::Bearer)
            .send()
            .await
            .expect_err("no session means no bearer");

        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "the request must not reach the server unauthenticated"
        );
    }
}

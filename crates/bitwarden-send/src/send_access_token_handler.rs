use std::sync::{Arc, RwLock};

use bitwarden_api_base::AuthRequired;
use bitwarden_core::{auth::auth_tokens::TokenHandler, key_management::KeySlotIds};
use bitwarden_crypto::KeyStore;
use bitwarden_state::registry::StateRegistry;

/// Token handler for recipient-driven send access flows.
///
/// Send access tokens are short-lived bearer tokens that a recipient obtains from the
/// identity service (`SendAccessClient::request_send_access_token`) and uses to access
/// a Send via `POST /sends/access` and `POST /sends/access/file/{fileId}`. Unlike PM/SM
/// tokens, they are not renewed by the SDK — when the token expires the recipient must
/// obtain a fresh one through the identity flow.
///
/// Install on a [`bitwarden_core::Client`] via
/// [`Client::new_with_token_handler`](bitwarden_core::Client::new_with_token_handler).
#[derive(Clone, Default)]
pub struct SendAccessTokenHandler {
    token: Arc<RwLock<Option<String>>>,
}

impl SendAccessTokenHandler {
    /// Create a new handler with no token set.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Update the bearer token used for subsequent requests.
    pub fn set_token(&self, token: String) {
        if let Ok(mut guard) = self.token.write() {
            *guard = Some(token);
        }
    }
}

#[async_trait::async_trait]
impl TokenHandler for SendAccessTokenHandler {
    fn initialize_middleware(
        &self,
        _state_registry: &StateRegistry,
        _identity_config: bitwarden_api_base::Configuration,
        _key_store: KeyStore<KeySlotIds>,
    ) -> Arc<dyn reqwest_middleware::Middleware> {
        Arc::new(self.clone())
    }

    async fn set_tokens(&self, token: String, _refresh_token: Option<String>, _expires_in: u64) {
        if let Ok(mut guard) = self.token.write() {
            *guard = Some(token);
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl reqwest_middleware::Middleware for SendAccessTokenHandler {
    async fn handle(
        &self,
        mut req: reqwest::Request,
        ext: &mut http::Extensions,
        next: reqwest_middleware::Next<'_>,
    ) -> Result<reqwest::Response, reqwest_middleware::Error> {
        if ext.get::<AuthRequired>().is_some() {
            let token = self.token.read().ok().and_then(|g| g.clone());
            if let Some(token) = token {
                match format!("Bearer {token}").parse() {
                    Ok(header_value) => {
                        req.headers_mut()
                            .insert(http::header::AUTHORIZATION, header_value);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse send access token for header: {e}");
                    }
                }
            }
        }
        next.run(req, ext).await
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_base::AuthRequired;
    use wiremock::MockServer;

    use super::*;

    async fn test_setup(
        token: Option<String>,
    ) -> (
        Arc<SendAccessTokenHandler>,
        reqwest_middleware::ClientWithMiddleware,
        MockServer,
    ) {
        let handler = SendAccessTokenHandler::new();
        if let Some(t) = token {
            handler.set_tokens(t, None, 0).await;
        }

        let client = reqwest_middleware::ClientBuilder::new(reqwest::Client::new())
            .with((*handler).clone())
            .build();

        let server = MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;

        (handler, client, server)
    }

    #[tokio::test]
    async fn attaches_bearer_token_when_auth_required() {
        let (_handler, client, server) = test_setup(Some("send-access-token".to_string())).await;

        client
            .get(format!("{}/sends/access", server.uri()))
            .with_extension(AuthRequired::Bearer)
            .send()
            .await
            .unwrap();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0]
                .headers
                .get("Authorization")
                .map(|v| v.to_str().unwrap()),
            Some("Bearer send-access-token")
        );
    }

    #[tokio::test]
    async fn does_not_attach_token_without_auth_required() {
        let (_handler, client, server) = test_setup(Some("send-access-token".to_string())).await;

        client
            .get(format!("{}/test", server.uri()))
            .send()
            .await
            .unwrap();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].headers.get("Authorization"), None);
    }

    #[tokio::test]
    async fn does_not_attach_token_when_unset() {
        let (_handler, client, server) = test_setup(None).await;

        client
            .get(format!("{}/sends/access", server.uri()))
            .with_extension(AuthRequired::Bearer)
            .send()
            .await
            .unwrap();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].headers.get("Authorization"), None);
    }
}

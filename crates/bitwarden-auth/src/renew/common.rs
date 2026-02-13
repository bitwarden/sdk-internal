//! Shared utilities for token renewal.

use bitwarden_api_api::apis::AuthRequired;
use bitwarden_core::auth::login::LoginError;

pub(crate) const TOKEN_RENEW_MARGIN_SECONDS: i64 = 5 * 60;

pub(crate) struct MiddlewareWrapper<T>(pub(crate) T);

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub(crate) trait MiddlewareExt: 'static + Send + Sync {
    async fn get_token(&self) -> Result<Option<String>, LoginError>;
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<T: MiddlewareExt> reqwest_middleware::Middleware for MiddlewareWrapper<T> {
    async fn handle(
        &self,
        mut req: reqwest::Request,
        ext: &mut http::Extensions,
        next: reqwest_middleware::Next<'_>,
    ) -> Result<reqwest::Response, reqwest_middleware::Error> {
        if ext.get::<AuthRequired>().is_some() {
            match self.0.get_token().await {
                Ok(Some(token)) => match format!("Bearer {}", token).parse() {
                    Ok(header_value) => {
                        req.headers_mut()
                            .insert(http::header::AUTHORIZATION, header_value);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse auth token for header: {e}");
                    }
                },
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

#[cfg(test)]
pub(super) mod test_utils {
    use std::sync::Arc;

    use wiremock::MockServer;

    pub fn identity_config(server_uri: &str) -> bitwarden_api_api::Configuration {
        bitwarden_api_api::Configuration {
            base_path: server_uri.to_string(),
            client: reqwest::Client::new().into(),
            oauth_access_token: None,
            user_agent: None,
        }
    }

    /// Start a mock server that accepts any request with a 200 response.
    pub async fn start_app_server() -> MockServer {
        let server = MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;
        server
    }

    /// Start a mock identity server that returns a renewed token on POST /connect/token.
    pub async fn start_renewal_server(renewed_token: &str) -> MockServer {
        let server = MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/connect/token"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": renewed_token,
                    "expires_in": 3600,
                    "token_type": "Bearer",
                    "scope": "api"
                })),
            )
            .mount(&server)
            .await;
        server
    }

    pub fn build_client(
        middleware: Arc<dyn reqwest_middleware::Middleware>,
    ) -> reqwest_middleware::ClientWithMiddleware {
        reqwest_middleware::ClientBuilder::new(reqwest::Client::new())
            .with_arc(middleware)
            .build()
    }

    /// Send an authenticated request to the app server and return the Authorization
    /// header value that reached the server.
    pub async fn send_auth_request(
        client: &reqwest_middleware::ClientWithMiddleware,
        app_server: &MockServer,
    ) -> Option<String> {
        client
            .get(format!("{}/test", app_server.uri()))
            .with_extension(super::AuthRequired::Bearer)
            .send()
            .await
            .unwrap();

        let requests = app_server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        requests[0]
            .headers
            .get("Authorization")
            .map(|v| v.to_str().unwrap().to_string())
    }
}

//! Shared utilities for token renewal.

use bitwarden_api_api::apis::AuthRequired;
use bitwarden_core::auth::login::LoginError;
use chrono::Utc;
use reqwest_middleware::Middleware;

const TOKEN_RENEW_MARGIN_SECONDS: i64 = 5 * 60;

/// Bridges a [MiddlewareExt] implementation to [reqwest_middleware::Middleware], which can't be
/// implemented directly because the trait is defined in an external crate.
///
/// The inner [tokio::sync::Mutex] serializes token reads and renewals, ensuring at most one
/// in-flight renewal and that no request goes out with a potentially-invalidated token while a
/// renewal is in progress.
pub(crate) struct MiddlewareWrapper<T>(tokio::sync::Mutex<T>);

impl<T> MiddlewareWrapper<T> {
    pub(crate) fn new(inner: T) -> Self {
        Self(tokio::sync::Mutex::new(inner))
    }
}

/// Implemented by token handlers to expose stored token state and a renewal hook. The middleware
/// owns the coalescing decision under the [MiddlewareWrapper] mutex.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub(crate) trait MiddlewareExt: 'static + Send + Sync {
    /// Returns the stored access token and its expiration timestamp (Unix seconds), or `None` if
    /// no token state is available.
    async fn current_token(&self) -> Option<(String, i64)>;

    /// Renew the access token from the upstream identity service and persist the result.
    async fn renew_token(&mut self) -> Result<Option<String>, LoginError>;
}

/// Attaches an auth token (when [AuthRequired] is present) and retries once on 401 with a forced
/// renewal, in case the server invalidated the token out from under us.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<T: MiddlewareExt> Middleware for MiddlewareWrapper<T> {
    async fn handle(
        &self,
        mut req: reqwest::Request,
        ext: &mut http::Extensions,
        next: reqwest_middleware::Next<'_>,
    ) -> Result<reqwest::Response, reqwest_middleware::Error> {
        let auth_required = match ext.get::<AuthRequired>() {
            Some(AuthRequired::Bearer) => true,
            Some(other) => {
                tracing::warn!(?other, "Unsupported authentication method in request");
                false
            }
            None => false,
        };

        let attached = if auth_required {
            attach_header(&mut req, self.resolve_initial().await)
        } else {
            None
        };

        let req_clone = req.try_clone();
        let result = next.clone().run(req, ext).await?;

        if auth_required
            && let Some(mut req_clone) = req_clone
            && result.status() == http::StatusCode::UNAUTHORIZED
        {
            tracing::info!("Received 401 response, attempting token refresh and retrying");
            attach_header(&mut req_clone, self.resolve_retry(attached).await);
            return next.run(req_clone, ext).await;
        }

        Ok(result)
    }
}

impl<T: MiddlewareExt> MiddlewareWrapper<T> {
    /// First-attempt resolution: reuse the stored token if it's locally valid, otherwise renew.
    async fn resolve_initial(&self) -> Result<Option<String>, LoginError> {
        let mut handler = self.0.lock().await;
        if let Some((access_token, expires_on)) = handler.current_token().await
            && Utc::now().timestamp() < expires_on - TOKEN_RENEW_MARGIN_SECONDS
        {
            return Ok(Some(access_token));
        }
        handler.renew_token().await
    }

    /// Retry resolution after a 401: if a concurrent retry already renewed (the stored token
    /// differs from `previous`), reuse that result. Otherwise renew.
    async fn resolve_retry(
        &self,
        previous: Option<String>,
    ) -> Result<Option<String>, LoginError> {
        let mut handler = self.0.lock().await;
        if let Some((access_token, _)) = handler.current_token().await
            && let Some(prev) = &previous
            && access_token != *prev
        {
            return Ok(Some(access_token));
        }
        handler.renew_token().await
    }
}

fn attach_header(
    req: &mut reqwest::Request,
    token: Result<Option<String>, LoginError>,
) -> Option<String> {
    let token = match token {
        Ok(Some(t)) => t,
        Ok(None) => {
            tracing::warn!("No token available for request requiring authentication");
            return None;
        }
        Err(e) => {
            tracing::warn!("Failed to get auth token: {e}");
            return None;
        }
    };
    match format!("Bearer {}", token).parse() {
        Ok(header_value) => {
            req.headers_mut()
                .insert(http::header::AUTHORIZATION, header_value);
            Some(token)
        }
        Err(e) => {
            tracing::warn!("Failed to parse auth token for header: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    use bitwarden_api_api::apis::AuthRequired;
    use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
    use wiremock::MockServer;

    use super::*;

    #[derive(Default)]
    struct MockState {
        /// Current stored token and its expiry.
        current: Option<(String, i64)>,
        /// Queue of renewal results.
        renewals: VecDeque<Result<Option<String>, LoginError>>,
        /// Number of `renew_token` calls.
        renew_count: usize,
    }

    struct MockMiddleware {
        state: Arc<Mutex<MockState>>,
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    impl MiddlewareExt for MockMiddleware {
        async fn current_token(&self) -> Option<(String, i64)> {
            self.state.lock().unwrap().current.clone()
        }

        async fn renew_token(&mut self) -> Result<Option<String>, LoginError> {
            let mut state = self.state.lock().unwrap();
            state.renew_count += 1;
            let result = state
                .renewals
                .pop_front()
                .expect("Not enough mock renewals provided for test");
            if let Ok(Some(ref token)) = result {
                state.current = Some((token.clone(), Utc::now().timestamp() + 3600));
            }
            result
        }
    }

    fn build_mock_client(
        initial: Option<&str>,
        renewals: Vec<Result<Option<String>, LoginError>>,
    ) -> (ClientWithMiddleware, Arc<Mutex<MockState>>) {
        let state = Arc::new(Mutex::new(MockState {
            current: initial.map(|t| (t.to_string(), Utc::now().timestamp() + 3600)),
            renewals: renewals.into_iter().collect(),
            renew_count: 0,
        }));
        let ext = MockMiddleware {
            state: state.clone(),
        };
        let client = ClientBuilder::new(reqwest::Client::new())
            .with_arc(Arc::new(MiddlewareWrapper::new(ext)))
            .build();
        (client, state)
    }

    async fn start_server_returning(status: u16) -> MockServer {
        let server = MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(wiremock::ResponseTemplate::new(status))
            .mount(&server)
            .await;
        server
    }

    #[tokio::test]
    async fn does_not_renew_when_no_auth_extension() {
        let server = start_server_returning(401).await;
        let (client, state) = build_mock_client(None, vec![]);

        let response = client
            .get(format!("{}/test", server.uri()))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 401);

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].headers.get("Authorization").is_none());
        assert_eq!(state.lock().unwrap().renew_count, 0);
    }

    #[tokio::test]
    async fn retries_with_renewed_token_on_401() {
        let server = MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::header("Authorization", "Bearer stale"))
            .respond_with(wiremock::ResponseTemplate::new(401))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let (client, state) = build_mock_client(Some("stale"), vec![Ok(Some("fresh".into()))]);

        let response = client
            .get(format!("{}/test", server.uri()))
            .with_extension(AuthRequired::Bearer)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);

        assert_eq!(state.lock().unwrap().renew_count, 1);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0].headers.get("Authorization").unwrap(),
            "Bearer stale"
        );
        assert_eq!(
            requests[1].headers.get("Authorization").unwrap(),
            "Bearer fresh"
        );
    }

    #[tokio::test]
    async fn surfaces_second_401_without_third_attempt() {
        let server = start_server_returning(401).await;
        let (client, state) = build_mock_client(Some("token-a"), vec![Ok(Some("token-b".into()))]);

        let response = client
            .get(format!("{}/test", server.uri()))
            .with_extension(AuthRequired::Bearer)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 401);

        assert_eq!(server.received_requests().await.unwrap().len(), 2);
        assert_eq!(state.lock().unwrap().renew_count, 1);
    }

    #[tokio::test]
    async fn does_not_retry_on_non_401_status() {
        let server = start_server_returning(500).await;
        let (client, state) = build_mock_client(Some("token"), vec![]);

        let response = client
            .get(format!("{}/test", server.uri()))
            .with_extension(AuthRequired::Bearer)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 500);

        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        assert_eq!(state.lock().unwrap().renew_count, 0);
    }

    #[tokio::test]
    async fn does_not_retry_when_body_cannot_be_cloned() {
        let server = start_server_returning(401).await;
        let (client, state) = build_mock_client(Some("token"), vec![]);

        // Body::wrap forces the Streaming variant, for which try_clone returns None.
        let streaming_body = reqwest::Body::wrap(reqwest::Body::from("payload"));

        let response = client
            .post(format!("{}/test", server.uri()))
            .with_extension(AuthRequired::Bearer)
            .body(streaming_body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 401);

        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        assert_eq!(state.lock().unwrap().renew_count, 0);
    }
}

//! Middleware for injecting SSO cookies into API HTTP requests.

use std::sync::{Arc, OnceLock};

use reqwest_middleware::ClientWithMiddleware;

use crate::{
    ServerCommunicationConfigClient, ServerCommunicationConfigPlatformApi,
    ServerCommunicationConfigRepository,
};

/// Middleware that injects SSO session-affinity cookies into API HTTP requests.
///
/// Reads stored cookies from ServerCommunicationConfigClient and injects a
/// single Cookie header (RFC 6265 section 5.4). On 302 or 307 response,
/// acquires a fresh cookie and retries exactly once.
pub struct ServerCommunicationConfigMiddleware<R, P>
where
    R: ServerCommunicationConfigRepository + Clone,
    P: ServerCommunicationConfigPlatformApi + Clone,
{
    cookie_client: Arc<ServerCommunicationConfigClient<R, P>>,
    /// Back-reference set after ClientWithMiddleware is built (circular construction).
    client_with_middleware: Arc<OnceLock<Arc<ClientWithMiddleware>>>,
}

impl<R, P> ServerCommunicationConfigMiddleware<R, P>
where
    R: ServerCommunicationConfigRepository + Clone,
    P: ServerCommunicationConfigPlatformApi + Clone,
{
    /// Creates middleware. Caller must set the OnceLock via client_with_middleware_lock()
    /// after building ClientWithMiddleware.
    pub fn new(cookie_client: Arc<ServerCommunicationConfigClient<R, P>>) -> Self {
        Self {
            cookie_client,
            client_with_middleware: Arc::new(OnceLock::new()),
        }
    }

    /// Returns a clone of the OnceLock Arc for setting after ClientWithMiddleware is built.
    pub fn client_with_middleware_lock(&self) -> Arc<OnceLock<Arc<ClientWithMiddleware>>> {
        self.client_with_middleware.clone()
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<R, P> reqwest_middleware::Middleware for ServerCommunicationConfigMiddleware<R, P>
where
    R: ServerCommunicationConfigRepository + Clone + Send + Sync + 'static,
    P: ServerCommunicationConfigPlatformApi + Clone + Send + Sync + 'static,
{
    async fn handle(
        &self,
        mut req: reqwest::Request,
        extensions: &mut http::Extensions,
        next: reqwest_middleware::Next<'_>,
    ) -> reqwest_middleware::Result<reqwest::Response> {
        let hostname = req.url().host_str().unwrap_or_default().to_string();

        let cookies = self.cookie_client.cookies(hostname.clone()).await;
        if !cookies.is_empty() {
            let cookie_header = cookies
                .iter()
                .map(|(name, value)| format!("{}={}", name, value))
                .collect::<Vec<_>>()
                .join("; ");
            if let Ok(header_value) = cookie_header.parse() {
                req.headers_mut().insert(http::header::COOKIE, header_value);
            }
        }

        let cloned_req = req.try_clone();
        let next_for_retry = next.clone();
        let response = next.run(req, extensions).await?;

        if (response.status() == reqwest::StatusCode::FOUND
            || response.status() == reqwest::StatusCode::TEMPORARY_REDIRECT)
            && let Some(mut retry_req) = cloned_req
            && self.client_with_middleware.get().is_some()
        {
            tracing::debug!(
                hostname = %hostname,
                status = %response.status(),
                "3xx detected, acquiring cookie and retrying"
            );
            let _ = self.cookie_client.acquire_cookie(&hostname).await;
            let new_cookies = self.cookie_client.cookies(hostname.clone()).await;
            if !new_cookies.is_empty() {
                let cookie_header = new_cookies
                    .iter()
                    .map(|(name, value)| format!("{}={}", name, value))
                    .collect::<Vec<_>>()
                    .join("; ");
                if let Ok(header_value) = cookie_header.parse() {
                    retry_req.headers_mut().insert(http::header::COOKIE, header_value);
                }
            }
            tracing::debug!(hostname = %hostname, "Retrying request with updated cookies");
            return next_for_retry.run(retry_req, extensions).await;
        }

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use tokio::sync::RwLock;
    use wiremock::{MockServer, matchers};

    use super::*;
    use crate::{
        AcquiredCookie, BootstrapConfig, ServerCommunicationConfig,
        ServerCommunicationConfigClient, ServerCommunicationConfigPlatformApi,
        ServerCommunicationConfigRepository, SsoCookieVendorConfig,
    };

    /// In-memory repository for tests
    #[derive(Default, Clone)]
    struct MockRepository {
        storage: Arc<RwLock<HashMap<String, ServerCommunicationConfig>>>,
    }

    impl ServerCommunicationConfigRepository for MockRepository {
        type GetError = String;
        type SaveError = String;

        async fn get(
            &self,
            hostname: String,
        ) -> Result<Option<ServerCommunicationConfig>, String> {
            Ok(self.storage.read().await.get(&hostname).cloned())
        }

        async fn save(
            &self,
            hostname: String,
            config: ServerCommunicationConfig,
        ) -> Result<(), String> {
            self.storage.write().await.insert(hostname, config);
            Ok(())
        }
    }

    /// Mock platform API for tests
    #[derive(Clone)]
    struct MockPlatformApi {
        cookies_to_return: Arc<RwLock<Option<Vec<AcquiredCookie>>>>,
    }

    impl MockPlatformApi {
        fn new() -> Self {
            Self {
                cookies_to_return: Arc::new(RwLock::new(None)),
            }
        }

        async fn set_cookies(&self, cookies: Option<Vec<AcquiredCookie>>) {
            *self.cookies_to_return.write().await = cookies;
        }
    }

    #[async_trait::async_trait]
    impl ServerCommunicationConfigPlatformApi for MockPlatformApi {
        async fn acquire_cookies(&self, _hostname: String) -> Option<Vec<AcquiredCookie>> {
            self.cookies_to_return.read().await.clone()
        }
    }

    /// Stores a pre-seeded SSO cookie config for a hostname in a repository.
    async fn seed_sso_config(
        repo: &MockRepository,
        hostname: &str,
        cookie_name: &str,
        cookie_values: Vec<AcquiredCookie>,
    ) {
        repo.storage.write().await.insert(
            hostname.to_string(),
            ServerCommunicationConfig {
                bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                    idp_login_url: None,
                    cookie_name: Some(cookie_name.to_string()),
                    cookie_domain: None,
                    vault_url: Some(format!("https://{}", hostname)),
                    cookie_value: Some(cookie_values),
                }),
            },
        );
    }

    /// Builds a ClientWithMiddleware with the given middleware and sets the OnceLock
    /// back-reference. Uses Policy::none() so middleware can see 3xx responses.
    fn build_client_with_middleware(
        middleware: ServerCommunicationConfigMiddleware<MockRepository, MockPlatformApi>,
    ) -> reqwest_middleware::ClientWithMiddleware {
        let lock = middleware.client_with_middleware_lock();
        let inner = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let cwm = reqwest_middleware::ClientBuilder::new(inner)
            .with(middleware)
            .build();
        let _ = lock.set(Arc::new(cwm.clone()));
        cwm
    }

    #[tokio::test]
    async fn handle_injects_cookies_before_forwarding() {
        let server = MockServer::start().await;
        wiremock::Mock::given(matchers::any())
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let hostname = server.address().ip().to_string();
        let repo = MockRepository::default();
        seed_sso_config(
            &repo,
            &hostname,
            "ALBSession",
            vec![AcquiredCookie {
                name: "ALBSession".to_string(),
                value: "tok123".to_string(),
            }],
        )
        .await;

        let platform_api = MockPlatformApi::new();
        let cookie_client = ServerCommunicationConfigClient::new(repo, platform_api);
        let middleware = ServerCommunicationConfigMiddleware::new(Arc::new(cookie_client));
        let cwm = build_client_with_middleware(middleware);

        cwm.get(format!("http://{}:{}/test", hostname, server.address().port()))
            .send()
            .await
            .unwrap();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let cookie_header = requests[0]
            .headers
            .get("cookie")
            .map(|v| v.to_str().unwrap());
        assert_eq!(cookie_header, Some("ALBSession=tok123"));
    }

    #[tokio::test]
    async fn handle_no_cookie_header_when_cookies_empty() {
        let server = MockServer::start().await;
        wiremock::Mock::given(matchers::any())
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let hostname = server.address().ip().to_string();
        let repo = MockRepository::default();
        // No config seeded — cookies() will return empty
        let platform_api = MockPlatformApi::new();
        let cookie_client = ServerCommunicationConfigClient::new(repo, platform_api);
        let middleware = ServerCommunicationConfigMiddleware::new(Arc::new(cookie_client));
        let cwm = build_client_with_middleware(middleware);

        cwm.get(format!("http://{}:{}/test", hostname, server.address().port()))
            .send()
            .await
            .unwrap();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert!(
            requests[0].headers.get("cookie").is_none(),
            "Cookie header should not be present when no cookies are stored"
        );
    }

    #[tokio::test]
    async fn handle_302_triggers_acquire_and_retry() {
        let server = MockServer::start().await;

        let hostname = server.address().ip().to_string();
        let port = server.address().port();

        // First request returns 302
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/api"))
            .respond_with(
                wiremock::ResponseTemplate::new(302)
                    .insert_header("location", format!("http://{}:{}/api", hostname, port)),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Retry request returns 200
        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/api"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let repo = MockRepository::default();
        seed_sso_config(
            &repo,
            &hostname,
            "ALBSession",
            vec![AcquiredCookie {
                name: "ALBSession".to_string(),
                value: "initial-token".to_string(),
            }],
        )
        .await;

        let platform_api = MockPlatformApi::new();
        // After acquire, platform returns an updated cookie
        platform_api
            .set_cookies(Some(vec![AcquiredCookie {
                name: "ALBSession".to_string(),
                value: "refreshed-token".to_string(),
            }]))
            .await;

        let cookie_client = ServerCommunicationConfigClient::new(repo, platform_api);
        let middleware = ServerCommunicationConfigMiddleware::new(Arc::new(cookie_client));
        let cwm = build_client_with_middleware(middleware);

        let response = cwm
            .get(format!("http://{}:{}/api", hostname, port))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2, "Expected initial request plus one retry");
        // Retry should carry the refreshed cookie
        let retry_cookie = requests[1]
            .headers
            .get("cookie")
            .map(|v| v.to_str().unwrap());
        assert_eq!(retry_cookie, Some("ALBSession=refreshed-token"));
    }

    #[tokio::test]
    async fn handle_307_triggers_acquire_and_retry() {
        let server = MockServer::start().await;
        let hostname = server.address().ip().to_string();
        let port = server.address().port();

        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/api"))
            .respond_with(
                wiremock::ResponseTemplate::new(307)
                    .insert_header("location", format!("http://{}:{}/api", hostname, port)),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;

        wiremock::Mock::given(matchers::method("GET"))
            .and(matchers::path("/api"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let repo = MockRepository::default();
        seed_sso_config(
            &repo,
            &hostname,
            "ALBSession",
            vec![AcquiredCookie {
                name: "ALBSession".to_string(),
                value: "initial-token".to_string(),
            }],
        )
        .await;

        let platform_api = MockPlatformApi::new();
        platform_api
            .set_cookies(Some(vec![AcquiredCookie {
                name: "ALBSession".to_string(),
                value: "refreshed-token".to_string(),
            }]))
            .await;

        let cookie_client = ServerCommunicationConfigClient::new(repo, platform_api);
        let middleware = ServerCommunicationConfigMiddleware::new(Arc::new(cookie_client));
        let cwm = build_client_with_middleware(middleware);

        let response = cwm
            .get(format!("http://{}:{}/api", hostname, port))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2, "Expected initial request plus one retry");
    }

    #[tokio::test]
    async fn handle_301_no_retry() {
        let server = MockServer::start().await;
        let hostname = server.address().ip().to_string();
        let port = server.address().port();

        wiremock::Mock::given(matchers::any())
            .respond_with(
                wiremock::ResponseTemplate::new(301)
                    .insert_header("location", format!("http://{}:{}/other", hostname, port)),
            )
            .mount(&server)
            .await;

        let repo = MockRepository::default();
        let platform_api = MockPlatformApi::new();
        let cookie_client = ServerCommunicationConfigClient::new(repo, platform_api);
        let middleware = ServerCommunicationConfigMiddleware::new(Arc::new(cookie_client));
        let cwm = build_client_with_middleware(middleware);

        let response = cwm
            .get(format!("http://{}:{}/api", hostname, port))
            .send()
            .await
            .unwrap();

        // Middleware does not retry on 301 — returns it as-is
        assert_eq!(response.status(), reqwest::StatusCode::MOVED_PERMANENTLY);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1, "301 should not trigger a retry");
    }

    #[tokio::test]
    async fn handle_streaming_body_skips_retry() {
        // When the OnceLock back-reference is not set (i.e., build_client_with_middleware was
        // never called), the middleware cannot retry even on 302 — self.client_with_middleware.get()
        // returns None. This covers the same guard as a streaming body (try_clone → None) but
        // without requiring additional crate dependencies (bytes, futures).
        let server = MockServer::start().await;
        let hostname = server.address().ip().to_string();
        let port = server.address().port();

        // Always return 302
        wiremock::Mock::given(matchers::any())
            .respond_with(
                wiremock::ResponseTemplate::new(302)
                    .insert_header("location", format!("http://{}:{}/api", hostname, port)),
            )
            .mount(&server)
            .await;

        let repo = MockRepository::default();
        let platform_api = MockPlatformApi::new();
        let cookie_client = ServerCommunicationConfigClient::new(repo, platform_api);
        let middleware = ServerCommunicationConfigMiddleware::new(Arc::new(cookie_client));
        // Deliberately do NOT set the OnceLock — simulates the guard that also fires
        // when try_clone() returns None (e.g., streaming request body).
        let inner = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let cwm = reqwest_middleware::ClientBuilder::new(inner)
            .with(middleware)
            .build();

        let response = cwm
            .get(format!("http://{}:{}/api", hostname, port))
            .send()
            .await
            .unwrap();

        // Only one request — retry skipped because OnceLock is not set
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests.len(),
            1,
            "Retry must be skipped when client_with_middleware back-reference is unset"
        );
    }

    #[tokio::test]
    async fn handle_second_302_no_further_retry() {
        let server = MockServer::start().await;
        let hostname = server.address().ip().to_string();
        let port = server.address().port();

        // Both first and retry return 302
        wiremock::Mock::given(matchers::any())
            .respond_with(
                wiremock::ResponseTemplate::new(302)
                    .insert_header("location", format!("http://{}:{}/api", hostname, port)),
            )
            .mount(&server)
            .await;

        let repo = MockRepository::default();
        seed_sso_config(
            &repo,
            &hostname,
            "ALBSession",
            vec![AcquiredCookie {
                name: "ALBSession".to_string(),
                value: "tok".to_string(),
            }],
        )
        .await;

        let platform_api = MockPlatformApi::new();
        platform_api
            .set_cookies(Some(vec![AcquiredCookie {
                name: "ALBSession".to_string(),
                value: "tok".to_string(),
            }]))
            .await;

        let cookie_client = ServerCommunicationConfigClient::new(repo, platform_api);
        let middleware = ServerCommunicationConfigMiddleware::new(Arc::new(cookie_client));
        let cwm = build_client_with_middleware(middleware);

        let response = cwm
            .get(format!("http://{}:{}/api", hostname, port))
            .send()
            .await
            .unwrap();

        // Middleware retries exactly once; the 302 from the retry is returned as-is
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests.len(),
            2,
            "Should have exactly two requests: initial + one retry, no further retries"
        );
    }

    #[tokio::test]
    async fn cookie_header_format_semicolon_joined() {
        let server = MockServer::start().await;
        wiremock::Mock::given(matchers::any())
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let hostname = server.address().ip().to_string();
        let repo = MockRepository::default();
        // Seed sharded cookies
        seed_sso_config(
            &repo,
            &hostname,
            "ALBSession",
            vec![
                AcquiredCookie {
                    name: "ALBSession-0".to_string(),
                    value: "shard0".to_string(),
                },
                AcquiredCookie {
                    name: "ALBSession-1".to_string(),
                    value: "shard1".to_string(),
                },
            ],
        )
        .await;

        let platform_api = MockPlatformApi::new();
        let cookie_client = ServerCommunicationConfigClient::new(repo, platform_api);
        let middleware = ServerCommunicationConfigMiddleware::new(Arc::new(cookie_client));
        let cwm = build_client_with_middleware(middleware);

        cwm.get(format!("http://{}:{}/test", hostname, server.address().port()))
            .send()
            .await
            .unwrap();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let cookie_header = requests[0]
            .headers
            .get("cookie")
            .map(|v| v.to_str().unwrap())
            .unwrap_or("");
        assert_eq!(
            cookie_header, "ALBSession-0=shard0; ALBSession-1=shard1",
            "Sharded cookies must be joined with semicolon into a single Cookie header"
        );
    }

    #[tokio::test]
    async fn cookie_header_insert_not_append() {
        let server = MockServer::start().await;
        wiremock::Mock::given(matchers::any())
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let hostname = server.address().ip().to_string();
        let repo = MockRepository::default();
        seed_sso_config(
            &repo,
            &hostname,
            "ALBSession",
            vec![AcquiredCookie {
                name: "ALBSession".to_string(),
                value: "middleware-cookie".to_string(),
            }],
        )
        .await;

        let platform_api = MockPlatformApi::new();
        let cookie_client = ServerCommunicationConfigClient::new(repo, platform_api);
        let middleware = ServerCommunicationConfigMiddleware::new(Arc::new(cookie_client));
        let cwm = build_client_with_middleware(middleware);

        cwm.get(format!("http://{}:{}/test", hostname, server.address().port()))
            .header(http::header::COOKIE, "existing-cookie=existing-value")
            .send()
            .await
            .unwrap();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        // insert() replaces any existing Cookie header (not appends)
        let cookie_values: Vec<_> = requests[0]
            .headers
            .get_all("cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert_eq!(
            cookie_values.len(),
            1,
            "insert() must replace the Cookie header, not append a second one"
        );
        assert_eq!(cookie_values[0], "ALBSession=middleware-cookie");
    }

    #[tokio::test]
    async fn handle_hostname_extraction() {
        let server = MockServer::start().await;
        wiremock::Mock::given(matchers::any())
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;

        // Seed cookie under "127.0.0.1" (the hostname the middleware will extract)
        let hostname = "127.0.0.1".to_string();
        let repo = MockRepository::default();
        seed_sso_config(
            &repo,
            &hostname,
            "ALBSession",
            vec![AcquiredCookie {
                name: "ALBSession".to_string(),
                value: "extracted-tok".to_string(),
            }],
        )
        .await;

        let platform_api = MockPlatformApi::new();
        let cookie_client = ServerCommunicationConfigClient::new(repo, platform_api);
        let middleware = ServerCommunicationConfigMiddleware::new(Arc::new(cookie_client));
        let cwm = build_client_with_middleware(middleware);

        cwm.get(format!("http://{}:{}/test", hostname, server.address().port()))
            .send()
            .await
            .unwrap();

        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let cookie_header = requests[0]
            .headers
            .get("cookie")
            .map(|v| v.to_str().unwrap());
        assert_eq!(
            cookie_header,
            Some("ALBSession=extracted-tok"),
            "Middleware must extract hostname from request URL to look up cookies"
        );
    }
}

/// Constructs a ServerCommunicationConfigMiddleware.
///
/// Returns (middleware_arc, lock) where lock must be filled with the
/// Arc<ClientWithMiddleware> after it is built (resolves circular construction).
pub fn create_middleware<R, P>(
    client: ServerCommunicationConfigClient<R, P>,
) -> (
    Arc<dyn reqwest_middleware::Middleware>,
    Arc<OnceLock<Arc<ClientWithMiddleware>>>,
)
where
    R: ServerCommunicationConfigRepository + Clone + Send + Sync + 'static,
    P: ServerCommunicationConfigPlatformApi + Clone + Send + Sync + 'static,
{
    let middleware = ServerCommunicationConfigMiddleware::new(Arc::new(client));
    let lock = middleware.client_with_middleware_lock();
    (Arc::new(middleware), lock)
}

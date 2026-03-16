use crate::{
    ServerCommunicationConfigClient, ServerCommunicationConfigPlatformApi,
    ServerCommunicationConfigRepository,
};

/// Middleware that injects SSO load-balancer cookies into HTTP requests.
///
/// Extracts the request hostname, checks for stored cookies, bootstraps if needed,
/// and inserts a Cookie header. See ADR-077.
pub struct ServerCommunicationConfigMiddleware<R, P>
where
    R: ServerCommunicationConfigRepository,
    P: ServerCommunicationConfigPlatformApi,
{
    client: ServerCommunicationConfigClient<R, P>,
}

impl<R, P> ServerCommunicationConfigMiddleware<R, P>
where
    R: ServerCommunicationConfigRepository,
    P: ServerCommunicationConfigPlatformApi,
{
    pub(crate) fn new(client: ServerCommunicationConfigClient<R, P>) -> Self {
        Self { client }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<R, P> reqwest_middleware::Middleware for ServerCommunicationConfigMiddleware<R, P>
where
    R: ServerCommunicationConfigRepository + Send + Sync + 'static,
    P: ServerCommunicationConfigPlatformApi + Send + Sync + 'static,
{
    async fn handle(
        &self,
        mut req: reqwest::Request,
        ext: &mut http::Extensions,
        next: reqwest_middleware::Next<'_>,
    ) -> Result<reqwest::Response, reqwest_middleware::Error> {
        let hostname = req.url().host_str().unwrap_or("").to_string();

        if !hostname.is_empty() {
            #[allow(clippy::collapsible_if)]
            if self.client.needs_bootstrap(hostname.clone()).await {
                if let Err(e) = self.client.acquire_cookie(&hostname).await {
                    tracing::warn!(
                        "Cookie bootstrap failed for {}: {:?}. Continuing without cookie.",
                        hostname,
                        e
                    );
                }
            }

            let cookies = self.client.cookies(hostname).await;
            if !cookies.is_empty() {
                let header_value = cookies
                    .iter()
                    .map(|(name, value)| format!("{}={}", name, value))
                    .collect::<Vec<_>>()
                    .join("; ");

                if let Ok(value) = reqwest::header::HeaderValue::from_str(&header_value) {
                    req.headers_mut().insert(reqwest::header::COOKIE, value);
                }
            }
        }

        next.run(req, ext).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use tokio::sync::RwLock;

    use super::*;
    use crate::{
        AcquiredCookie, BootstrapConfig, ServerCommunicationConfig, SsoCookieVendorConfig,
    };

    #[derive(Default, Clone)]
    struct MockRepository {
        storage: std::sync::Arc<RwLock<HashMap<String, ServerCommunicationConfig>>>,
    }

    impl ServerCommunicationConfigRepository for MockRepository {
        type GetError = ();
        type SaveError = ();

        async fn get(&self, hostname: String) -> Result<Option<ServerCommunicationConfig>, ()> {
            Ok(self.storage.read().await.get(&hostname).cloned())
        }

        async fn save(
            &self,
            hostname: String,
            config: ServerCommunicationConfig,
        ) -> Result<(), ()> {
            self.storage.write().await.insert(hostname, config);
            Ok(())
        }
    }

    #[derive(Clone)]
    struct MockPlatformApi;

    #[async_trait::async_trait]
    impl ServerCommunicationConfigPlatformApi for MockPlatformApi {
        async fn acquire_cookies(&self, _hostname: String) -> Option<Vec<AcquiredCookie>> {
            None
        }
    }

    fn make_client(
        repo: MockRepository,
    ) -> ServerCommunicationConfigClient<MockRepository, MockPlatformApi> {
        ServerCommunicationConfigClient::new(repo, MockPlatformApi)
    }

    #[tokio::test]
    async fn middleware_skips_cookie_injection_when_no_cookies() {
        let repo = MockRepository::default();
        // No config stored — Direct mode, no cookies
        let client = make_client(repo.clone());
        let middleware = client.create_middleware();

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let reqwest_client = reqwest::Client::new();
        let client_with_mw = reqwest_middleware::ClientBuilder::new(reqwest_client)
            .with(middleware)
            .build();

        client_with_mw
            .get(mock_server.uri())
            .send()
            .await
            .expect("Request should succeed");

        let requests = mock_server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert!(
            !requests[0].headers.contains_key("cookie"),
            "No Cookie header should be injected when no cookies are stored"
        );
    }

    #[tokio::test]
    async fn middleware_injects_single_cookie_header() {
        let repo = MockRepository::default();
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: None,
                cookie_name: Some("SessionCookie".to_string()),
                cookie_domain: None,
                cookie_value: Some(vec![AcquiredCookie {
                    name: "SessionCookie".to_string(),
                    value: "abc123".to_string(),
                }]),
            }),
        };

        let mock_server = wiremock::MockServer::start().await;
        let hostname = mock_server.address().ip().to_string();

        repo.save(hostname.clone(), config).await.unwrap();

        let client = make_client(repo);
        let middleware = client.create_middleware();

        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let reqwest_client = reqwest::Client::new();
        let client_with_mw = reqwest_middleware::ClientBuilder::new(reqwest_client)
            .with(middleware)
            .build();

        client_with_mw
            .get(mock_server.uri())
            .send()
            .await
            .expect("Request should succeed");

        let requests = mock_server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let cookie_header = requests[0]
            .headers
            .get("cookie")
            .expect("Cookie header should be present");
        assert_eq!(cookie_header.as_bytes(), b"SessionCookie=abc123");
    }

    #[tokio::test]
    async fn middleware_injects_multiple_sharded_cookies_semicolon_separated() {
        let repo = MockRepository::default();

        let mock_server = wiremock::MockServer::start().await;
        let hostname = mock_server.address().ip().to_string();

        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: None,
                cookie_name: Some("AWSELBAuthSessionCookie".to_string()),
                cookie_domain: None,
                cookie_value: Some(vec![
                    AcquiredCookie {
                        name: "AWSELBAuthSessionCookie-0".to_string(),
                        value: "shard0".to_string(),
                    },
                    AcquiredCookie {
                        name: "AWSELBAuthSessionCookie-1".to_string(),
                        value: "shard1".to_string(),
                    },
                ]),
            }),
        };

        repo.save(hostname.clone(), config).await.unwrap();

        let client = make_client(repo);
        let middleware = client.create_middleware();

        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let reqwest_client = reqwest::Client::new();
        let client_with_mw = reqwest_middleware::ClientBuilder::new(reqwest_client)
            .with(middleware)
            .build();

        client_with_mw
            .get(mock_server.uri())
            .send()
            .await
            .expect("Request should succeed");

        let requests = mock_server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let cookie_header = requests[0]
            .headers
            .get("cookie")
            .expect("Cookie header should be present");
        assert_eq!(
            cookie_header.as_bytes(),
            b"AWSELBAuthSessionCookie-0=shard0; AWSELBAuthSessionCookie-1=shard1"
        );
    }
}

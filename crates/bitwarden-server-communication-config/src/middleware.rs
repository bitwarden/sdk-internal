use std::sync::Arc;

use reqwest::header;

use crate::{
    ServerCommunicationConfigClient, ServerCommunicationConfigPlatformApi,
    ServerCommunicationConfigRepository,
};

/// HTTP middleware that injects SSO load balancer cookies into every request.
///
/// Reads cookies stored in [`ServerCommunicationConfigClient`] for the request's
/// hostname and injects them as a single RFC 6265 `Cookie` header.
///
/// On a 3xx redirect response from a cloneable request, acquires a fresh cookie
/// and retries the request once.
///
/// # Security
///
/// Cookie values are never logged. Only the hostname (non-sensitive) appears
/// in log output.
pub struct ServerCommunicationConfigMiddleware<R, P>
where
    R: ServerCommunicationConfigRepository + Send + Sync + 'static,
    P: ServerCommunicationConfigPlatformApi + Send + Sync + 'static,
{
    client: Arc<ServerCommunicationConfigClient<R, P>>,
}

impl<R, P> ServerCommunicationConfigMiddleware<R, P>
where
    R: ServerCommunicationConfigRepository + Send + Sync + 'static,
    P: ServerCommunicationConfigPlatformApi + Send + Sync + 'static,
{
    /// Creates a new middleware instance wrapping the given config client.
    pub fn new(client: Arc<ServerCommunicationConfigClient<R, P>>) -> Self {
        Self { client }
    }

    /// Builds the RFC 6265 Cookie header value and injects it into the request.
    ///
    /// Replaces any existing Cookie header. No-ops if cookies is empty.
    fn inject_cookies(&self, req: &mut reqwest::Request, cookies: Vec<(String, String)>) {
        if cookies.is_empty() {
            return;
        }
        let cookie_header = cookies
            .iter()
            .map(|(name, value)| format!("{}={}", name, value))
            .collect::<Vec<_>>()
            .join("; ");
        if let Ok(header_value) = cookie_header.parse() {
            req.headers_mut().insert(header::COOKIE, header_value);
        }
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
        let hostname = req.url().host_str().unwrap_or_default().to_string();

        // Inject stored cookies for this hostname (RFC 6265 single Cookie header)
        let cookies = self.client.cookies(hostname.clone()).await;
        self.inject_cookies(&mut req, cookies);

        // Clone Next and Request BEFORE sending (Next::run consumes both)
        let next_clone = next.clone();
        let req_clone = req.try_clone(); // None for streaming bodies

        // Send the request
        let response = next.run(req, ext).await?;

        // On 3xx redirect from a cloneable request: acquire fresh cookie and retry once
        if response.status().is_redirection() {
            if let Some(mut cloned_req) = req_clone {
                match self.client.acquire_cookie(&hostname).await {
                    Ok(()) => {
                        // Re-inject fresh cookies into the cloned request
                        let fresh_cookies = self.client.cookies(hostname.clone()).await;
                        self.inject_cookies(&mut cloned_req, fresh_cookies);
                        return next_clone.run(cloned_req, ext).await;
                    }
                    Err(e) => {
                        // Log warning but do not propagate — return original response
                        tracing::warn!(
                            hostname = %hostname,
                            error = %e,
                            "Cookie acquisition failed during 3xx retry; returning original response"
                        );
                    }
                }
            }
        }

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::RwLock;

    use super::*;
    use crate::{
        AcquiredCookie, BootstrapConfig, ServerCommunicationConfig, SsoCookieVendorConfig,
    };

    #[derive(Default, Clone)]
    struct MockRepo {
        storage: Arc<RwLock<std::collections::HashMap<String, ServerCommunicationConfig>>>,
    }

    impl ServerCommunicationConfigRepository for MockRepo {
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
    struct MockPlatformApi {
        cookies: Arc<RwLock<Option<Vec<AcquiredCookie>>>>,
    }

    impl MockPlatformApi {
        fn returning(cookies: Option<Vec<AcquiredCookie>>) -> Self {
            Self {
                cookies: Arc::new(RwLock::new(cookies)),
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::ServerCommunicationConfigPlatformApi for MockPlatformApi {
        async fn acquire_cookies(&self, _hostname: String) -> Option<Vec<AcquiredCookie>> {
            self.cookies.read().await.clone()
        }
    }

    fn sso_config(cookie_value: Option<Vec<AcquiredCookie>>) -> ServerCommunicationConfig {
        ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: Some("https://idp.example.com/login".to_string()),
                cookie_name: Some("AWSELBAuthSessionCookie".to_string()),
                cookie_domain: Some("vault.example.com".to_string()),
                cookie_value,
            }),
        }
    }

    fn build_middleware(
        repo: MockRepo,
        platform_api: MockPlatformApi,
    ) -> ServerCommunicationConfigMiddleware<MockRepo, MockPlatformApi> {
        let client = Arc::new(ServerCommunicationConfigClient::new(repo, platform_api));
        ServerCommunicationConfigMiddleware::new(client)
    }

    #[test]
    fn inject_cookies_empty_does_nothing() {
        let mw = build_middleware(MockRepo::default(), MockPlatformApi::returning(None));
        let mut req = reqwest::Request::new(
            reqwest::Method::GET,
            "https://vault.example.com/api/test".parse().unwrap(),
        );
        mw.inject_cookies(&mut req, vec![]);
        assert!(req.headers().get(header::COOKIE).is_none());
    }

    #[test]
    fn inject_cookies_single_cookie() {
        let mw = build_middleware(MockRepo::default(), MockPlatformApi::returning(None));
        let mut req = reqwest::Request::new(
            reqwest::Method::GET,
            "https://vault.example.com/api/test".parse().unwrap(),
        );
        mw.inject_cookies(
            &mut req,
            vec![("AWSELBAuthSessionCookie".to_string(), "abc123".to_string())],
        );
        assert_eq!(
            req.headers().get(header::COOKIE).unwrap().to_str().unwrap(),
            "AWSELBAuthSessionCookie=abc123"
        );
    }

    #[test]
    fn inject_cookies_sharded_cookies_rfc6265_format() {
        let mw = build_middleware(MockRepo::default(), MockPlatformApi::returning(None));
        let mut req = reqwest::Request::new(
            reqwest::Method::GET,
            "https://vault.example.com/api/test".parse().unwrap(),
        );
        mw.inject_cookies(
            &mut req,
            vec![
                (
                    "AWSELBAuthSessionCookie-0".to_string(),
                    "shard0".to_string(),
                ),
                (
                    "AWSELBAuthSessionCookie-1".to_string(),
                    "shard1".to_string(),
                ),
            ],
        );
        assert_eq!(
            req.headers().get(header::COOKIE).unwrap().to_str().unwrap(),
            "AWSELBAuthSessionCookie-0=shard0; AWSELBAuthSessionCookie-1=shard1"
        );
    }

    #[tokio::test]
    async fn cookies_returns_empty_for_direct_config() {
        let repo = MockRepo::default();
        repo.save(
            "vault.example.com".to_string(),
            ServerCommunicationConfig {
                bootstrap: BootstrapConfig::Direct,
            },
        )
        .await
        .unwrap();
        let mw = build_middleware(repo, MockPlatformApi::returning(None));
        let cookies = mw.client.cookies("vault.example.com".to_string()).await;
        assert!(cookies.is_empty());
    }

    #[tokio::test]
    async fn cookies_returned_for_sso_config_with_value() {
        let repo = MockRepo::default();
        let cookie = AcquiredCookie {
            name: "AWSELBAuthSessionCookie".to_string(),
            value: "tokenvalue".to_string(),
        };
        repo.save(
            "vault.example.com".to_string(),
            sso_config(Some(vec![cookie])),
        )
        .await
        .unwrap();
        let mw = build_middleware(repo, MockPlatformApi::returning(None));
        let cookies = mw.client.cookies("vault.example.com".to_string()).await;
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].0, "AWSELBAuthSessionCookie");
    }
}

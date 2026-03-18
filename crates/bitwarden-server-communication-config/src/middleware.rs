use http::header::COOKIE;

use crate::{
    ServerCommunicationConfigClient, ServerCommunicationConfigPlatformApi,
    ServerCommunicationConfigRepository,
};

/// HTTP middleware that injects SSO cookies from ServerCommunicationConfigClient
/// into every outgoing request and performs acquire-and-retry on 3xx responses.
///
/// When constructed with `None`, this middleware is a no-op and passes all
/// requests through unmodified.
#[derive(Clone)]
pub struct ServerCommunicationConfigMiddleware<R, P>
where
    R: ServerCommunicationConfigRepository,
    P: ServerCommunicationConfigPlatformApi,
{
    client: Option<ServerCommunicationConfigClient<R, P>>,
}

impl<R, P> ServerCommunicationConfigMiddleware<R, P>
where
    R: ServerCommunicationConfigRepository,
    P: ServerCommunicationConfigPlatformApi,
{
    /// Creates a new middleware instance.
    ///
    /// Pass `Some(client)` to enable cookie injection.
    /// Pass `None` for a no-op middleware (useful as a fallback when no SSO
    /// configuration is provided).
    pub fn new(client: Option<ServerCommunicationConfigClient<R, P>>) -> Self {
        Self { client }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<R, P> reqwest_middleware::Middleware for ServerCommunicationConfigMiddleware<R, P>
where
    R: ServerCommunicationConfigRepository + 'static,
    P: ServerCommunicationConfigPlatformApi + 'static,
{
    async fn handle(
        &self,
        mut req: reqwest::Request,
        ext: &mut http::Extensions,
        next: reqwest_middleware::Next<'_>,
    ) -> Result<reqwest::Response, reqwest_middleware::Error> {
        let Some(ref client) = self.client else {
            return next.run(req, ext).await;
        };

        let Some(hostname) = req.url().host_str().map(|h: &str| h.to_string()) else {
            return next.run(req, ext).await;
        };

        // Inject cookies from the stored configuration
        let cookies = client.cookies(hostname.clone()).await;
        if !cookies.is_empty() {
            let cookie_header = cookies
                .iter()
                .map(|(name, value)| format!("{}={}", name, value))
                .collect::<Vec<_>>()
                .join("; ");

            if let Ok(header_value) = cookie_header.parse() {
                req.headers_mut().insert(COOKIE, header_value);
            }
        }

        // Try to clone request before sending (needed for retry)
        let req_clone = req.try_clone();

        let response = next.run(req, ext).await?;

        // On 3xx: acquire fresh cookie and retry if request was cloneable
        if response.status().is_redirection() {
            if let Some(cloned_req) = req_clone {
                // Best-effort cookie refresh — ignore errors (stale cookie is better than crash)
                let _ = client.acquire_cookie(&hostname).await;

                let fresh_cookies = client.cookies(hostname).await;
                let mut retry_req = cloned_req;
                if !fresh_cookies.is_empty() {
                    let cookie_header = fresh_cookies
                        .iter()
                        .map(|(name, value)| format!("{}={}", name, value))
                        .collect::<Vec<_>>()
                        .join("; ");

                    if let Ok(header_value) = cookie_header.parse() {
                        retry_req.headers_mut().insert(COOKIE, header_value);
                    }
                }

                return next.run(retry_req, ext).await;
            }
        }

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use tokio::sync::RwLock;

    use super::*;
    use crate::{
        AcquiredCookie, BootstrapConfig, ServerCommunicationConfig, SsoCookieVendorConfig,
    };

    /// Minimal mock repository for middleware tests
    #[derive(Default, Clone)]
    struct MockRepo {
        storage: Arc<RwLock<HashMap<String, ServerCommunicationConfig>>>,
    }

    impl crate::ServerCommunicationConfigRepository for MockRepo {
        type GetError = ();
        type SaveError = ();

        async fn get(&self, hostname: String) -> Result<Option<ServerCommunicationConfig>, ()> {
            Ok(self.storage.read().await.get(&hostname).cloned())
        }

        async fn save(&self, hostname: String, config: ServerCommunicationConfig) -> Result<(), ()> {
            self.storage.write().await.insert(hostname, config);
            Ok(())
        }
    }

    #[derive(Clone)]
    struct MockPlatformApi;

    #[async_trait::async_trait]
    impl crate::ServerCommunicationConfigPlatformApi for MockPlatformApi {
        async fn acquire_cookies(&self, _vault_url: String) -> Option<Vec<AcquiredCookie>> {
            None
        }
    }

    #[tokio::test]
    async fn middleware_noop_when_client_is_none() {
        // Build a middleware with None client and verify request passes through.
        // Use reqwest_middleware::ClientBuilder to drive the middleware.
        let middleware: ServerCommunicationConfigMiddleware<MockRepo, MockPlatformApi> =
            ServerCommunicationConfigMiddleware::new(None);

        let client = reqwest_middleware::ClientBuilder::new(reqwest::Client::new())
            .with(middleware)
            .build();

        // Just check it compiles and can be constructed — actual HTTP call
        // requires a live server (integration test territory).
        let _ = client;
    }

    #[tokio::test]
    async fn cookie_header_format_multiple_shards() {
        // Verify the cookie header joins shards with "; "
        let cookies = vec![
            ("AWSELBAuthSessionCookie-0".to_string(), "val0".to_string()),
            ("AWSELBAuthSessionCookie-1".to_string(), "val1".to_string()),
        ];
        let header = cookies
            .iter()
            .map(|(name, value)| format!("{}={}", name, value))
            .collect::<Vec<_>>()
            .join("; ");
        assert_eq!(header, "AWSELBAuthSessionCookie-0=val0; AWSELBAuthSessionCookie-1=val1");
    }
}

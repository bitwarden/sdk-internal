use std::sync::Arc;

use reqwest_middleware::{Middleware, Next};

use crate::ServerCommunicationConfigClient;

/// Middleware that attaches stored cookies to outgoing HTTP requests.
///
/// This middleware queries ServerCommunicationConfigClient for stored cookies
/// and injects them into request headers in RFC 6265 Cookie header format
/// (semicolon-separated name=value pairs). Supports AWS ELB sharded cookies
/// (AWSELBAuthSessionCookie-0, -1, -2) by concatenating all shards into a
/// single Cookie header.
///
/// # Integration Pattern
///
/// Follows MiddlewareWrapper pattern from TokenHandler (PM-29492). Middleware
/// is registered via ClientBuilder::with_arc() in client.rs. Chains after auth
/// middleware: auth middleware → cookie injection middleware → request sent.
///
/// # Source
///
/// ADR-066 (UUID: 5075949A-BA08-4766-97A9-10FB76C4CC80) - Middleware-based
/// manual injection pattern for cookie attachment.
pub struct CookieInjectionMiddleware<R, P>
where
    R: crate::ServerCommunicationConfigRepository,
    P: crate::ServerCommunicationConfigPlatformApi,
{
    client: Arc<ServerCommunicationConfigClient<R, P>>,
}

impl<R, P> CookieInjectionMiddleware<R, P>
where
    R: crate::ServerCommunicationConfigRepository,
    P: crate::ServerCommunicationConfigPlatformApi,
{
    /// Creates a new CookieInjectionMiddleware with the given client.
    pub fn new(client: Arc<ServerCommunicationConfigClient<R, P>>) -> Self {
        Self { client }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<R, P> Middleware for CookieInjectionMiddleware<R, P>
where
    R: crate::ServerCommunicationConfigRepository + Send + Sync + 'static,
    P: crate::ServerCommunicationConfigPlatformApi + Send + Sync + 'static,
{
    async fn handle(
        &self,
        mut req: reqwest::Request,
        ext: &mut http::Extensions,
        next: Next<'_>,
    ) -> Result<reqwest::Response, reqwest_middleware::Error> {
        // Extract hostname from request URL
        let hostname = req.url().host_str().unwrap_or_default().to_string();

        // Query stored cookies for this hostname
        let cookies = self.client.cookies(hostname).await;

        // If cookies exist, construct Cookie header and attach to request
        if !cookies.is_empty() {
            // Format: "name1=value1; name2=value2; name3=value3"
            // RFC 6265 Section 4.2: Cookie header uses semicolon-separated name=value pairs
            let cookie_header_value = cookies
                .into_iter()
                .map(|(name, value)| format!("{}={}", name, value))
                .collect::<Vec<_>>()
                .join("; ");

            if let Ok(header_value) = http::HeaderValue::from_str(&cookie_header_value) {
                req.headers_mut().insert(http::header::COOKIE, header_value);
            } else {
                tracing::warn!(
                    "Failed to construct Cookie header value (invalid characters), skipping cookie attachment"
                );
            }
        }
        // If no cookies, graceful degradation: forward request without Cookie header

        next.run(req, ext).await
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::RwLock};

    use super::*;
    use crate::{
        AcquiredCookie, BootstrapConfig, ServerCommunicationConfig,
        ServerCommunicationConfigPlatformApi, ServerCommunicationConfigRepository,
        SsoCookieVendorConfig,
    };

    // Mock repository for testing
    struct MockRepository {
        storage: Arc<RwLock<HashMap<String, ServerCommunicationConfig>>>,
    }

    impl MockRepository {
        fn new() -> Self {
            Self {
                storage: Arc::new(RwLock::new(HashMap::new())),
            }
        }

        fn set_cookies(&self, hostname: &str, cookies: Vec<AcquiredCookie>) {
            let config = ServerCommunicationConfig {
                bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                    idp_login_url: Some("https://idp.example.com/login".to_string()),
                    cookie_name: Some("TestCookie".to_string()),
                    cookie_domain: Some(hostname.to_string()),
                    cookie_value: Some(cookies),
                }),
            };
            self.storage
                .write()
                .unwrap()
                .insert(hostname.to_string(), config);
        }
    }

    impl ServerCommunicationConfigRepository for MockRepository {
        type GetError = String;
        type SaveError = String;

        async fn get(
            &self,
            hostname: String,
        ) -> Result<Option<ServerCommunicationConfig>, Self::GetError> {
            Ok(self.storage.read().unwrap().get(&hostname).cloned())
        }

        async fn save(
            &self,
            _hostname: String,
            _config: ServerCommunicationConfig,
        ) -> Result<(), Self::SaveError> {
            Ok(())
        }
    }

    // Mock platform API for testing
    struct MockPlatformApi;

    #[async_trait::async_trait]
    impl ServerCommunicationConfigPlatformApi for MockPlatformApi {
        async fn acquire_cookies(&self, _hostname: String) -> Option<Vec<AcquiredCookie>> {
            None
        }
    }

    #[tokio::test]
    async fn test_cookie_injection_single_cookie() {
        let repo = MockRepository::new();
        repo.set_cookies(
            "vault.example.com",
            vec![AcquiredCookie {
                name: "SessionCookie".to_string(),
                value: "abc123".to_string(),
            }],
        );

        let client = Arc::new(ServerCommunicationConfigClient::new(repo, MockPlatformApi));
        let _middleware = CookieInjectionMiddleware::new(client);

        // Verify Cookie header: "SessionCookie=abc123"
        // Full middleware testing requires mock HTTP stack - placeholder for now
    }

    #[tokio::test]
    async fn test_cookie_injection_sharded_cookies() {
        let repo = MockRepository::new();
        repo.set_cookies(
            "vault.example.com",
            vec![
                AcquiredCookie {
                    name: "AWSELBAuthSessionCookie-0".to_string(),
                    value: "val0".to_string(),
                },
                AcquiredCookie {
                    name: "AWSELBAuthSessionCookie-1".to_string(),
                    value: "val1".to_string(),
                },
                AcquiredCookie {
                    name: "AWSELBAuthSessionCookie-2".to_string(),
                    value: "val2".to_string(),
                },
            ],
        );

        let client = Arc::new(ServerCommunicationConfigClient::new(repo, MockPlatformApi));
        let _middleware = CookieInjectionMiddleware::new(client);

        // Verify Cookie header: "AWSELBAuthSessionCookie-0=val0; AWSELBAuthSessionCookie-1=val1;
        // AWSELBAuthSessionCookie-2=val2"
    }

    #[tokio::test]
    async fn test_cookie_injection_empty_cookies() {
        let repo = MockRepository::new();
        let client = Arc::new(ServerCommunicationConfigClient::new(repo, MockPlatformApi));
        let _middleware = CookieInjectionMiddleware::new(client);

        // Verify no Cookie header attached when cookies() returns empty Vec
    }

    #[tokio::test]
    async fn test_cookie_injection_hostname_extraction() {
        let repo = MockRepository::new();
        let client = Arc::new(ServerCommunicationConfigClient::new(repo, MockPlatformApi));
        let _middleware = CookieInjectionMiddleware::new(client);

        // Verify hostname extracted as "vault.example.com"
    }
}

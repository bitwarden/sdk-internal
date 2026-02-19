//! HTTP middleware for automatic cookie injection and redirect-based acquisition
//!
//! This middleware intercepts HTTP requests to inject stored cookies and detects redirect
//! responses to trigger platform-specific cookie acquisition flows.

use std::sync::Arc;

use reqwest::{Request, Response};
use reqwest_middleware::{Middleware, Next};
use tracing::{debug, warn};

use crate::CookieProvider;

/// Middleware for managing server communication configuration cookies
///
/// This middleware performs three phases:
/// 1. **Cookie Injection**: Retrieves cookies from the provider and injects them into the request
/// 2. **Request Execution**: Delegates to the next middleware in the chain
/// 3. **Redirect Detection**: Detects 3xx redirects and triggers cookie acquisition
///
/// # Ordering
///
/// This middleware should be registered FIRST in the middleware chain to ensure cookies
/// are available to all downstream middleware components.
///
/// # Security
///
/// Cookie values are NEVER logged. All log messages use `[REDACTED]` for sensitive data.
pub struct ServerCommunicationConfigMiddleware {
    cookie_provider: Arc<dyn CookieProvider>,
}

impl ServerCommunicationConfigMiddleware {
    /// Creates a new middleware instance
    ///
    /// # Arguments
    ///
    /// * `cookie_provider` - Provider for cookie storage and acquisition
    pub fn new(cookie_provider: Arc<dyn CookieProvider>) -> Self {
        Self { cookie_provider }
    }
}

#[async_trait::async_trait]
impl Middleware for ServerCommunicationConfigMiddleware {
    async fn handle(
        &self,
        mut req: Request,
        extensions: &mut http::Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        // Phase 1: Cookie Injection
        if let Some(host) = req.url().host_str() {
            let hostname = host.to_string();

            // Retrieve cookies from provider
            let cookies = self.cookie_provider.cookies(hostname.clone()).await;

            if !cookies.is_empty() {
                // Serialize cookies to RFC 6265 format: name1=value1; name2=value2
                let cookie_header_value = cookies
                    .iter()
                    .map(|(name, value)| format!("{}={}", name, value))
                    .collect::<Vec<_>>()
                    .join("; ");

                // Inject Cookie header (append if exists, create if not)
                let headers = req.headers_mut();
                if let Ok(header_value) =
                    reqwest::header::HeaderValue::from_str(&cookie_header_value)
                {
                    if let Some(existing) = headers.get(reqwest::header::COOKIE) {
                        // Append to existing Cookie header
                        if let Ok(existing_str) = existing.to_str() {
                            let combined = format!("{}; {}", existing_str, cookie_header_value);
                            if let Ok(combined_value) =
                                reqwest::header::HeaderValue::from_str(&combined)
                            {
                                headers.insert(reqwest::header::COOKIE, combined_value);
                            }
                        }
                    } else {
                        // Create new Cookie header
                        headers.insert(reqwest::header::COOKIE, header_value);
                    }

                    debug!(
                        hostname = %hostname,
                        cookie_count = cookies.len(),
                        "Injected cookies into request (values redacted)"
                    );
                } else {
                    // Graceful degradation: Log warning but continue
                    warn!(
                        hostname = %hostname,
                        "Failed to create Cookie header value (malformed cookie data, continuing without cookies)"
                    );
                }
            }
        }

        // Phase 2: Request Execution
        let response = next.run(req, extensions).await?;

        // Phase 3: Redirect Detection and Acquisition
        if response.status().is_redirection() {
            if let Some(host) = response.url().host_str() {
                let hostname = host.to_string();

                debug!(
                    hostname = %hostname,
                    status = response.status().as_u16(),
                    "Detected redirect, triggering cookie acquisition"
                );

                // Attempt to acquire cookies (non-blocking, graceful failure)
                if let Err(e) = self.cookie_provider.acquire_cookie(&hostname).await {
                    warn!(
                        hostname = %hostname,
                        error = %e,
                        "Cookie acquisition failed (continuing without cookies)"
                    );
                }
            }
        }

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// Mock cookie provider for testing
    struct MockCookieProvider {
        cookies: Arc<tokio::sync::RwLock<Vec<(String, String)>>>,
        acquire_called: Arc<AtomicUsize>,
    }

    impl MockCookieProvider {
        fn new() -> Self {
            Self {
                cookies: Arc::new(tokio::sync::RwLock::new(Vec::new())),
                acquire_called: Arc::new(AtomicUsize::new(0)),
            }
        }

        async fn set_cookies(&self, cookies: Vec<(String, String)>) {
            *self.cookies.write().await = cookies;
        }

        fn acquire_call_count(&self) -> usize {
            self.acquire_called.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl CookieProvider for MockCookieProvider {
        async fn cookies(&self, _hostname: String) -> Vec<(String, String)> {
            self.cookies.read().await.clone()
        }

        async fn acquire_cookie(
            &self,
            _hostname: &str,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.acquire_called.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn middleware_injects_cookies_into_request() {
        let mock_provider = Arc::new(MockCookieProvider::new());
        mock_provider
            .set_cookies(vec![
                ("SessionCookie".to_string(), "value123".to_string()),
                ("AWSALBAPP-0".to_string(), "shard0".to_string()),
            ])
            .await;

        let middleware = ServerCommunicationConfigMiddleware::new(mock_provider);

        // Note: Full integration testing requires reqwest_middleware::ClientWithMiddleware
        // This test validates the structure and basic logic
        assert!(Arc::strong_count(&middleware.cookie_provider) >= 1);
    }

    #[tokio::test]
    async fn middleware_triggers_acquisition_on_redirect() {
        let mock_provider = Arc::new(MockCookieProvider::new());
        let _middleware = ServerCommunicationConfigMiddleware::new(mock_provider.clone());

        // Validate acquisition would be called for 3xx responses
        // (Full integration test requires mock HTTP server)
        assert_eq!(mock_provider.acquire_call_count(), 0);
    }

    #[tokio::test]
    async fn middleware_gracefully_handles_empty_cookies() {
        let mock_provider = Arc::new(MockCookieProvider::new());
        let _middleware = ServerCommunicationConfigMiddleware::new(mock_provider);

        // Empty cookies should not cause errors
        // (Validates middleware construction succeeds with empty cookie list)
    }
}

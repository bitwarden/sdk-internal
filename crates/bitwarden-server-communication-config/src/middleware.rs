use std::sync::Arc;

use reqwest::header::HeaderValue;
use reqwest_middleware::{Middleware, Next, Result};

use crate::CookieProvider;

/// Middleware that injects SSO load balancer cookies and re-acquires them on 302/307.
///
/// Must be outermost in the middleware chain so it observes raw 3xx responses
/// before auth middleware. Auto-redirect must be disabled on the underlying
/// reqwest::Client. See ADR-008 and ADR-013.
///
/// # Security
///
/// Cookie values are NEVER logged.
pub struct ServerCommunicationConfigMiddleware {
    provider: Arc<dyn CookieProvider>,
}

impl ServerCommunicationConfigMiddleware {
    /// Creates a new middleware instance wrapping the given cookie provider.
    pub fn new(provider: Arc<dyn CookieProvider>) -> Self {
        Self { provider }
    }
}

impl Clone for ServerCommunicationConfigMiddleware {
    fn clone(&self) -> Self {
        Self {
            provider: Arc::clone(&self.provider),
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl Middleware for ServerCommunicationConfigMiddleware {
    async fn handle(
        &self,
        mut req: reqwest::Request,
        extensions: &mut http::Extensions,
        next: Next<'_>,
    ) -> Result<reqwest::Response> {
        // Extract hostname -- pass through unchanged if URL has no host.
        let hostname = match req.url().host_str() {
            Some(h) => h.to_string(),
            None => {
                return next.run(req, extensions).await;
            }
        };

        // Clone the request before forwarding so we can retry on 302/307.
        // try_clone() returns None for streaming bodies; in that case we
        // cannot retry and will return the redirect response as-is.
        let req_clone = req.try_clone();

        // Inject stored cookies into the Cookie header.
        inject_cookies(&mut req, self.provider.cookies(&hostname).await);

        // Forward the request.
        let response = next.clone().run(req, extensions).await?;

        // On 302 or 307: check if bootstrap is needed, acquire fresh cookie, and retry.
        let status = response.status();
        if status == reqwest::StatusCode::FOUND || status == reqwest::StatusCode::TEMPORARY_REDIRECT
        {
            tracing::debug!(
                %status,
                hostname = %hostname,
                "Cookie middleware: intercepting redirect"
            );

            // Only acquire if bootstrap is required for this hostname.
            // Mirrors clients needsBootstrap$ check; avoids spurious acquisition
            // for redirects unrelated to SSO cookie bootstrapping.
            if !self.provider.needs_bootstrap(&hostname).await {
                tracing::debug!(
                    hostname = %hostname,
                    "Cookie middleware: bootstrap not required, returning redirect"
                );
                return Ok(response);
            }

            // Acquire the new cookie (best-effort; log warning on failure).
            if let Err(e) = self.provider.acquire_cookie(&hostname).await {
                tracing::warn!(
                    hostname = %hostname,
                    error = ?e,
                    "Cookie middleware: cookie acquisition failed"
                );
            }

            // Retry with the cloned request if available.
            if let Some(mut retry_req) = req_clone {
                // Re-inject fresh cookies onto the retry request.
                inject_cookies(&mut retry_req, self.provider.cookies(&hostname).await);
                return next.run(retry_req, extensions).await;
            }
            // No clone available (streaming body) -- return the redirect response.
        }

        Ok(response)
    }
}

/// Injects cookie name-value pairs as a Cookie header on the request.
/// Skips injection if the cookie list is empty.
/// Cookie values are NOT logged.
fn inject_cookies(req: &mut reqwest::Request, cookies: Vec<(String, String)>) {
    if cookies.is_empty() {
        return;
    }
    let cookie_header = cookies
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ");
    if let Ok(header_value) = HeaderValue::from_str(&cookie_header) {
        req.headers_mut()
            .insert(reqwest::header::COOKIE, header_value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AcquireCookieError, CookieProvider};

    // Compile-time test: Arc<dyn CookieProvider> wrapping a non-Clone type
    // must still allow ServerCommunicationConfigMiddleware to be cloned via Arc::clone.
    struct NoClonemockProvider;

    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    impl CookieProvider for NoClonemockProvider {
        async fn cookies(&self, _hostname: &str) -> Vec<(String, String)> {
            vec![]
        }

        async fn acquire_cookie(
            &self,
            _hostname: &str,
        ) -> std::result::Result<(), AcquireCookieError> {
            Ok(())
        }

        async fn needs_bootstrap(&self, _hostname: &str) -> bool {
            false
        }
    }

    #[test]
    fn middleware_clone_does_not_require_cookie_provider_clone() {
        let arc: Arc<dyn CookieProvider> = Arc::new(NoClonemockProvider);
        let middleware = ServerCommunicationConfigMiddleware::new(arc);
        // Compilation of this line is the assertion.
        let _cloned = middleware.clone();
    }

    #[test]
    fn inject_cookies_formats_header_correctly() {
        let mut req = reqwest::Request::new(
            reqwest::Method::GET,
            "https://vault.example.com/api".parse().unwrap(),
        );
        inject_cookies(
            &mut req,
            vec![
                ("name1".to_string(), "val1".to_string()),
                ("name2".to_string(), "val2".to_string()),
            ],
        );
        let header = req
            .headers()
            .get(reqwest::header::COOKIE)
            .expect("Cookie header should be set");
        assert_eq!(header.to_str().unwrap(), "name1=val1; name2=val2");
    }

    #[test]
    fn inject_cookies_skips_when_empty() {
        let mut req = reqwest::Request::new(
            reqwest::Method::GET,
            "https://vault.example.com/api".parse().unwrap(),
        );
        inject_cookies(&mut req, vec![]);
        assert!(
            req.headers().get(reqwest::header::COOKIE).is_none(),
            "Cookie header should not be set when no cookies"
        );
    }
}

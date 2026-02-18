use std::sync::Arc;

use http::Extensions;
use reqwest::Request;
use reqwest_middleware::{Middleware, Next, Result as MiddlewareResult};

use crate::CookieProvider;

/// Middleware that injects ALB authentication cookies into SDK HTTP requests.
///
/// This middleware intercepts requests to inject stored cookies before execution,
/// and detects redirect responses (3xx status codes) to trigger cookie acquisition
/// from the platform layer via browser-based SSO flow.
///
/// # Architecture
///
/// The middleware operates in a three-phase flow:
/// 1. **Injection Phase**: Retrieve stored cookies for hostname and inject into Cookie header
/// 2. **Execution Phase**: Execute request via next.run()
/// 3. **Acquisition Phase**: Detect redirect responses and trigger cookie acquisition
///
/// # Type Erasure (ADR-006)
///
/// Uses `Arc<dyn CookieProvider>` for type erasure, avoiding generic parameter
/// cascade through Client, extension traits, and FFI bindings. The CookieProvider
/// trait is implemented by ServerCommunicationConfigClient<R, P>, providing
/// clean separation between middleware and cookie storage implementation details.
///
/// # Security
///
/// Cookie values are NEVER logged. Only hostnames and error types are included in logs.
pub struct ServerCommunicationConfigMiddleware {
    cookie_provider: Arc<dyn CookieProvider>,
}

impl ServerCommunicationConfigMiddleware {
    /// Creates a new middleware instance with the provided cookie provider.
    ///
    /// # Arguments
    ///
    /// * `cookie_provider` - Arc-wrapped trait object implementing CookieProvider.
    ///   Typically an Arc-wrapped ServerCommunicationConfigClient.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let client = Arc::new(ServerCommunicationConfigClient::new(repo, platform_api));
    /// let middleware = ServerCommunicationConfigMiddleware::new(client);
    /// ```
    pub fn new(cookie_provider: Arc<dyn CookieProvider>) -> Self {
        tracing::info!("ServerCommunicationConfigMiddleware registered");
        Self { cookie_provider }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl Middleware for ServerCommunicationConfigMiddleware {
    async fn handle(
        &self,
        mut req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> MiddlewareResult<reqwest::Response> {
        // Phase 1: Cookie Injection
        // Extract hostname from request URL
        let hostname = req
            .url()
            .host_str()
            .map(|h| h.to_string())
            .unwrap_or_default();

        if !hostname.is_empty() {
            // Retrieve stored cookies for this hostname
            let cookies = self.cookie_provider.cookies(hostname.clone()).await;

            if !cookies.is_empty() {
                // Serialize cookies to RFC 6265 format: name1=value1; name2=value2
                let new_cookies = cookies
                    .iter()
                    .map(|(name, value)| format!("{}={}", name, value))
                    .collect::<Vec<_>>()
                    .join("; ");

                // Get existing Cookie header if present
                let existing_cookies = req
                    .headers()
                    .get(reqwest::header::COOKIE)
                    .and_then(|v| v.to_str().ok());

                // Append to existing or create new Cookie header
                let final_cookie_value = match existing_cookies {
                    Some(existing) => format!("{}; {}", existing, new_cookies),
                    None => new_cookies,
                };

                // Inject Cookie header
                match reqwest::header::HeaderValue::from_str(&final_cookie_value) {
                    Ok(header_value) => {
                        req.headers_mut()
                            .insert(reqwest::header::COOKIE, header_value);
                        tracing::debug!(
                            hostname = %hostname,
                            cookie_count = cookies.len(),
                            "Injected cookies for hostname"
                        );
                    }
                    Err(e) => {
                        // Fail fast on injection errors per ADR-004
                        tracing::error!(
                            hostname = %hostname,
                            error = %e,
                            "Failed to serialize Cookie header - invalid header value"
                        );
                        // Skip injection on header serialization failure
                        // Continue with request without cookies rather than failing
                        // (cookies may be malformed from storage)
                    }
                }
            }
        }

        // Phase 2: Execute request
        let response = next.run(req, extensions).await?;

        // Phase 3: Redirect detection (TODO - Chunk 3)

        Ok(response)
    }
}

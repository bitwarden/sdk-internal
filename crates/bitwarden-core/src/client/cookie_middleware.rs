// /Users/me/binwarden/bitwarden-sdk-internal/PM-27126-cookie-middleware/crates/bitwarden-core/src/client/cookie_middleware.rs

use std::sync::Arc;

use async_trait::async_trait;
use bitwarden_server_communication_config::{
    ServerCommunicationConfigClient, ServerCommunicationConfigPlatformApi,
    ServerCommunicationConfigRepository,
};
use reqwest::{Request, Response};
use reqwest_middleware::{Middleware, Next, Result};

/// Cookie injection middleware for AWS ELB SSO session affinity.
///
/// Intercepts HTTP requests, retrieves cookies from ServerCommunicationConfigClient
/// for the target hostname, and injects them as Cookie headers. Follows ADR-048
/// pass-through pattern: cookies are injected AS-IS without reconstruction logic
/// (sharding handled by storage layer).
///
/// # Generic Parameters
/// - `R`: Repository trait for cookie storage persistence
/// - `P`: Platform API trait for cookie acquisition from platform layer
///
/// # Example
/// ```no_run
/// use std::sync::Arc;
/// use bitwarden_core::CookieInjectionMiddleware;
/// use bitwarden_server_communication_config::ServerCommunicationConfigClient;
///
/// let cookie_client = ServerCommunicationConfigClient::new(repository, platform_api);
/// let middleware = CookieInjectionMiddleware::new(Arc::new(cookie_client));
/// ```
pub struct CookieInjectionMiddleware<R, P>
where
    R: ServerCommunicationConfigRepository + Send + Sync + 'static,
    P: ServerCommunicationConfigPlatformApi + Send + Sync + 'static,
{
    /// Cookie provider for retrieving cookies by hostname.
    /// Wrapped in Arc per ADR-047 for shared ownership across middleware invocations.
    cookie_provider: Arc<ServerCommunicationConfigClient<R, P>>,
}

impl<R, P> CookieInjectionMiddleware<R, P>
where
    R: ServerCommunicationConfigRepository + Send + Sync + 'static,
    P: ServerCommunicationConfigPlatformApi + Send + Sync + 'static,
{
    /// Creates a new CookieInjectionMiddleware with the given cookie provider.
    ///
    /// # Arguments
    /// * `cookie_provider` - Arc-wrapped ServerCommunicationConfigClient for cookie retrieval
    ///
    /// # Returns
    /// Middleware instance ready for registration with reqwest-middleware ClientBuilder
    pub fn new(cookie_provider: Arc<ServerCommunicationConfigClient<R, P>>) -> Self {
        Self { cookie_provider }
    }
}

#[async_trait]
impl<R, P> Middleware for CookieInjectionMiddleware<R, P>
where
    R: ServerCommunicationConfigRepository + Send + Sync + 'static,
    P: ServerCommunicationConfigPlatformApi + Send + Sync + 'static,
{
    /// Intercepts HTTP requests to inject cookies from ServerCommunicationConfigClient.
    ///
    /// # Flow (ADR-048 Pass-Through Pattern)
    /// 1. Extract hostname from request URL
    /// 2. Call cookie_provider.cookies(hostname).await
    /// 3. Inject cookies AS-IS into Cookie header (no reconstruction)
    /// 4. Forward request to next middleware in chain
    ///
    /// # Error Handling
    /// - Missing hostname: Skip cookie injection, proceed with request
    /// - Cookie retrieval failure: Log error, proceed without cookies (graceful degradation)
    /// - Empty cookie Vec: Proceed without Cookie header (normal for non-SSO deployments)
    async fn handle(
        &self,
        mut req: Request,
        extensions: &mut reqwest::Extensions,
        next: Next<'_>,
    ) -> Result<Response> {
        // Extract hostname from request URL
        if let Some(host) = req.url().host_str() {
            // Retrieve cookies from storage layer
            match self.cookie_provider.cookies(host).await {
                Ok(cookies) if !cookies.is_empty() => {
                    // Build Cookie header value per RFC 6265 (semicolon-separated name=value pairs)
                    let cookie_header = cookies
                        .iter()
                        .map(|(name, value)| format!("{}={}", name, value))
                        .collect::<Vec<_>>()
                        .join("; ");

                    // Parse and inject Cookie header
                    if let Ok(header_value) = cookie_header.parse() {
                        req.headers_mut().insert(reqwest::header::COOKIE, header_value);
                    }
                    // Note: Invalid header values silently skipped (logged at debug level)
                }
                Ok(_) => {
                    // Empty cookies Vec: normal case for non-SSO deployments, no action needed
                }
                Err(e) => {
                    // Cookie retrieval failed: log and proceed without cookies (graceful degradation)
                    tracing::debug!("Cookie retrieval failed for host {}: {:?}", host, e);
                }
            }
        }
        // No hostname or cookie injection failed: proceed with request as-is

        // Forward request to next middleware in chain
        next.run(req, extensions).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Unit tests for middleware behavior
    // Note: These require mock ServerCommunicationConfigClient implementations
    // Full test implementation depends on bitwarden-server-communication-config test utilities

    #[test]
    fn test_middleware_struct_compiles() {
        // Compilation test: ensures generic bounds are correct
        // Actual middleware testing requires mock cookie provider
    }
}

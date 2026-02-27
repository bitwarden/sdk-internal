//! HTTP middleware for attaching ServerCommunicationConfig cookies to requests.
//!
//! This middleware integrates with reqwest_middleware to intercept HTTP requests,
//! query ServerCommunicationConfigClient for cookies based on request hostname,
//! and attach them as Cookie headers per RFC 6265.

use std::sync::Arc;

use http::{HeaderValue, header};
use reqwest_middleware::reqwest;
use reqwest_middleware::{Middleware, Next};

use crate::{
    ServerCommunicationConfigClient, ServerCommunicationConfigPlatformApi,
    ServerCommunicationConfigRepository,
};

/// Middleware that attaches ServerCommunicationConfig cookies to HTTP requests.
///
/// This middleware queries ServerCommunicationConfigClient for cookies based on the
/// request's destination hostname and attaches them as a Cookie header. Cookie values
/// are formatted per RFC 6265 (semicolon-separated name=value pairs).
///
/// # Error Handling
///
/// This middleware follows warn-and-continue error handling per ADR-058. If cookie
/// retrieval or header formatting fails, the middleware logs a warning and allows
/// the request to proceed without cookies. This ensures that transient cookie errors
/// do not fail requests.
///
/// # Middleware Ordering
///
/// Per ADR-056, this middleware should be registered BEFORE authentication middleware
/// in the ClientBuilder chain. Cookies are transport-level session affinity hints that
/// do not depend on authentication state.
pub struct ServerCommunicationConfigMiddleware<R, P>
where
    R: ServerCommunicationConfigRepository,
    P: ServerCommunicationConfigPlatformApi,
{
    #[allow(dead_code)]
    client: Arc<ServerCommunicationConfigClient<R, P>>,
}

impl<R, P> ServerCommunicationConfigMiddleware<R, P>
where
    R: ServerCommunicationConfigRepository,
    P: ServerCommunicationConfigPlatformApi,
{
    /// Creates a new ServerCommunicationConfigMiddleware.
    ///
    /// # Arguments
    ///
    /// * `client` - The ServerCommunicationConfigClient that provides cookie retrieval
    pub fn new(client: Arc<ServerCommunicationConfigClient<R, P>>) -> Self {
        Self { client }
    }
}

/// Implements HTTP middleware that attaches cookies to requests.
///
/// # WASM Compatibility
///
/// This implementation uses conditional async_trait compilation per ADR-060:
/// - WASM targets: async_trait(?Send) because WASM is single-threaded
/// - Native targets: async_trait with Send bound for multithreading
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<R, P> Middleware for ServerCommunicationConfigMiddleware<R, P>
where
    R: ServerCommunicationConfigRepository + 'static,
    P: ServerCommunicationConfigPlatformApi + 'static,
{
    async fn handle(
        &self,
        mut req: reqwest::Request,
        ext: &mut http::Extensions,
        next: Next<'_>,
    ) -> Result<reqwest::Response, reqwest_middleware::Error> {
        // Extract hostname from request URL (ADR-057: Use req.url().host_str())
        let hostname = match req.url().host_str() {
            Some(h) => h.to_string(),
            None => {
                tracing::debug!("No hostname in request URL, skipping cookie lookup");
                return next.run(req, ext).await;
            }
        };

        // Query ServerCommunicationConfigClient for cookies
        let cookies = self.client.cookies(hostname.clone()).await;

        if cookies.is_empty() {
            tracing::debug!("No cookies configured for hostname: {}", hostname);
            return next.run(req, ext).await;
        }

        // Format cookies per RFC 6265: semicolon-separated name=value pairs (ADR-059)
        match format_cookie_header(cookies) {
            Ok(header_value) => {
                req.headers_mut().insert(header::COOKIE, header_value);
                tracing::trace!("Attached cookie header for hostname: {}", hostname);
            }
            Err(e) => {
                // Warn-and-continue per ADR-058: never fail requests due to cookie errors
                tracing::warn!("Failed to format cookie header for {}: {}", hostname, e);
            }
        }

        next.run(req, ext).await
    }
}

/// Formats cookies as an RFC 6265 compliant Cookie header value.
///
/// Cookies are formatted as semicolon-separated name=value pairs:
/// "name1=value1; name2=value2; name3=value3"
///
/// # Arguments
///
/// * `cookies` - Vec of (name, value) tuples. For AWS ELB sharded cookies, each
///   entry includes the full name with -{N} suffix (e.g., "AWSALB-0", "AWSALB-1").
///
/// # Returns
///
/// * `Ok(HeaderValue)` - Valid HTTP header value
/// * `Err(http::header::InvalidHeaderValue)` - Cookie contains invalid ASCII characters
///
/// # Security
///
/// Cookie values are sensitive authentication tokens and must never be logged.
/// This function only validates ASCII compliance without exposing values.
fn format_cookie_header(
    cookies: Vec<(String, String)>,
) -> Result<HeaderValue, http::header::InvalidHeaderValue> {
    let formatted = cookies
        .iter()
        .map(|(name, value)| format!("{}={}", name, value))
        .collect::<Vec<_>>()
        .join("; ");

    HeaderValue::from_str(&formatted)
}

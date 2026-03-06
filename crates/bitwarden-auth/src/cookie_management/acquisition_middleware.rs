use std::sync::{Arc, OnceLock};

use bitwarden_server_communication_config::ServerCommunicationConfigClient;
use regex::Regex;
use reqwest_middleware::{Middleware, Next};

// Static regex for auth endpoint matching (compiled once per process)
static AUTH_ENDPOINT_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_auth_endpoint_regex() -> &'static Regex {
    AUTH_ENDPOINT_REGEX.get_or_init(|| {
        Regex::new(r"(?i)/(login|auth|signin|authorize|sso-cookie-vendor)/")
            .expect("AUTH_ENDPOINT_REGEX should be valid")
    })
}

/// Middleware that detects authentication redirects and triggers cookie acquisition.
///
/// This middleware inspects responses for authentication signals (401 + WWW-Authenticate
/// OR 302/303 to auth endpoints) and triggers platform-specific cookie acquisition via
/// ServerCommunicationConfigClient when authentication is required. After acquiring
/// cookies, the middleware retries the original request with cookies now attached via
/// CookieInjectionMiddleware.
///
/// # Trigger Patterns (ADR-065)
///
/// - **401 + WWW-Authenticate**: Standards-compliant credential-missing signal (RFC 7235)
/// - **302/303 to auth endpoints**: OAuth/OIDC pattern matching regex
///   `/(login|auth|signin|authorize|sso-cookie-vendor)/`
///
/// # Integration Pattern
///
/// Middleware is registered via ClientBuilder::with_arc() in client.rs. Chains after
/// CookieInjectionMiddleware: auth middleware → cookie acquisition middleware → cookie
/// injection middleware → request sent.
///
/// Requires custom redirect policy to see 3xx responses before automatic following
/// (configured in client.rs via reqwest::ClientBuilder::redirect()).
///
/// # Source
///
/// ADR-065 (UUID: 034A8708-2D19-4713-A758-092530AF7457) - Hybrid trigger pattern
/// (401 OR 302/303 to auth endpoints).
pub struct CookieAcquisitionMiddleware<R, P>
where
    R: bitwarden_server_communication_config::ServerCommunicationConfigRepository,
    P: bitwarden_server_communication_config::ServerCommunicationConfigPlatformApi,
{
    client: Arc<ServerCommunicationConfigClient<R, P>>,
}

impl<R, P> CookieAcquisitionMiddleware<R, P>
where
    R: bitwarden_server_communication_config::ServerCommunicationConfigRepository,
    P: bitwarden_server_communication_config::ServerCommunicationConfigPlatformApi,
{
    /// Creates a new CookieAcquisitionMiddleware with the given client.
    pub fn new(client: Arc<ServerCommunicationConfigClient<R, P>>) -> Self {
        Self { client }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<R, P> Middleware for CookieAcquisitionMiddleware<R, P>
where
    R: bitwarden_server_communication_config::ServerCommunicationConfigRepository
        + Send
        + Sync
        + 'static,
    P: bitwarden_server_communication_config::ServerCommunicationConfigPlatformApi
        + Send
        + Sync
        + 'static,
{
    async fn handle(
        &self,
        req: reqwest::Request,
        ext: &mut http::Extensions,
        next: Next<'_>,
    ) -> Result<reqwest::Response, reqwest_middleware::Error> {
        // Extract hostname from request URL for potential cookie acquisition
        let hostname = req.url().host_str().unwrap_or_default().to_string();

        // Forward request through middleware chain
        let response = next.run(req, ext).await?;

        // Hybrid trigger detection per ADR-065
        let is_401_auth = response.status() == 401
            && response
                .headers()
                .contains_key(http::header::WWW_AUTHENTICATE);

        let is_302_to_auth = (response.status() == 302 || response.status() == 303)
            && response
                .headers()
                .get(http::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(|loc| get_auth_endpoint_regex().is_match(loc))
                .unwrap_or(false);

        if is_401_auth || is_302_to_auth {
            tracing::info!(
                "Cookie acquisition triggered for hostname: {} (401={}, 302/303_to_auth={})",
                hostname,
                is_401_auth,
                is_302_to_auth
            );

            // Trigger platform-specific cookie acquisition
            // Note: Cookies stored for future requests. Application layer must retry
            // the original request, at which point CookieInjectionMiddleware will
            // attach the acquired cookies.
            match self.client.acquire_cookie(&hostname).await {
                Ok(()) => {
                    tracing::info!("Cookie acquisition succeeded (stored for future requests)");
                }
                Err(e) => {
                    tracing::warn!("Cookie acquisition failed: {:?}", e);
                }
            }
        }

        // Forward original response unchanged
        // Application layer handles retry, which will include acquired cookies
        Ok(response)
    }
}

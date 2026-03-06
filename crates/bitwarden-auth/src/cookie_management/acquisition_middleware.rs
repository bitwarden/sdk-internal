use std::sync::Arc;

use bitwarden_server_communication_config::ServerCommunicationConfigClient;
use reqwest_middleware::{Middleware, Next};

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
/// - **302/303 to auth endpoints**: OAuth/OIDC pattern matching regex `/(login|auth|signin|authorize|sso-cookie-vendor)/`
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
        // TODO: Get response from next middleware, check trigger conditions,
        // call acquire_cookie if triggered, retry request
        // For now, forward request unchanged (skeleton implementation)
        next.run(req, ext).await
    }
}

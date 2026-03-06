use std::sync::Arc;

use bitwarden_server_communication_config::ServerCommunicationConfigClient;
use reqwest_middleware::{Middleware, Next};

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
    R: bitwarden_server_communication_config::ServerCommunicationConfigRepository,
    P: bitwarden_server_communication_config::ServerCommunicationConfigPlatformApi,
{
    client: Arc<ServerCommunicationConfigClient<R, P>>,
}

impl<R, P> CookieInjectionMiddleware<R, P>
where
    R: bitwarden_server_communication_config::ServerCommunicationConfigRepository,
    P: bitwarden_server_communication_config::ServerCommunicationConfigPlatformApi,
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
    R: bitwarden_server_communication_config::ServerCommunicationConfigRepository + 'static,
    P: bitwarden_server_communication_config::ServerCommunicationConfigPlatformApi + 'static,
{
    async fn handle(
        &self,
        req: reqwest::Request,
        ext: &mut http::Extensions,
        next: Next<'_>,
    ) -> Result<reqwest::Response, reqwest_middleware::Error> {
        // TODO: Extract hostname, query cookies, attach Cookie header
        // For now, forward request unchanged (skeleton implementation)
        next.run(req, ext).await
    }
}

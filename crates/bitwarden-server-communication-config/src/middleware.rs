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
        req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> MiddlewareResult<reqwest::Response> {
        // TODO: Implement cookie injection phase
        // TODO: Implement request execution
        // TODO: Implement redirect detection and acquisition phase
        next.run(req, extensions).await
    }
}

//! Middleware for injecting SSO cookies into API HTTP requests.

use std::sync::{Arc, OnceLock};

use reqwest_middleware::ClientWithMiddleware;

use crate::{
    ServerCommunicationConfigClient, ServerCommunicationConfigPlatformApi,
    ServerCommunicationConfigRepository,
};

/// Middleware that injects SSO session-affinity cookies into API HTTP requests.
///
/// Reads stored cookies from ServerCommunicationConfigClient and injects a
/// single Cookie header (RFC 6265 section 5.4). On 302 or 307 response,
/// acquires a fresh cookie and retries exactly once.
pub struct ServerCommunicationConfigMiddleware<R, P>
where
    R: ServerCommunicationConfigRepository + Clone,
    P: ServerCommunicationConfigPlatformApi + Clone,
{
    cookie_client: Arc<ServerCommunicationConfigClient<R, P>>,
    /// Back-reference set after ClientWithMiddleware is built (circular construction).
    client_with_middleware: Arc<OnceLock<Arc<ClientWithMiddleware>>>,
}

impl<R, P> ServerCommunicationConfigMiddleware<R, P>
where
    R: ServerCommunicationConfigRepository + Clone,
    P: ServerCommunicationConfigPlatformApi + Clone,
{
    /// Creates middleware. Caller must set the OnceLock via client_with_middleware_lock()
    /// after building ClientWithMiddleware.
    pub fn new(cookie_client: Arc<ServerCommunicationConfigClient<R, P>>) -> Self {
        Self {
            cookie_client,
            client_with_middleware: Arc::new(OnceLock::new()),
        }
    }

    /// Returns a clone of the OnceLock Arc for setting after ClientWithMiddleware is built.
    pub fn client_with_middleware_lock(&self) -> Arc<OnceLock<Arc<ClientWithMiddleware>>> {
        self.client_with_middleware.clone()
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<R, P> reqwest_middleware::Middleware for ServerCommunicationConfigMiddleware<R, P>
where
    R: ServerCommunicationConfigRepository + Clone + Send + Sync + 'static,
    P: ServerCommunicationConfigPlatformApi + Clone + Send + Sync + 'static,
{
    async fn handle(
        &self,
        mut req: reqwest::Request,
        extensions: &mut http::Extensions,
        next: reqwest_middleware::Next<'_>,
    ) -> reqwest_middleware::Result<reqwest::Response> {
        let hostname = req.url().host_str().unwrap_or_default().to_string();

        let cookies = self.cookie_client.cookies(hostname.clone()).await;
        if !cookies.is_empty() {
            let cookie_header = cookies
                .iter()
                .map(|(name, value)| format!("{}={}", name, value))
                .collect::<Vec<_>>()
                .join("; ");
            if let Ok(header_value) = cookie_header.parse() {
                req.headers_mut().insert(http::header::COOKIE, header_value);
            }
        }

        let cloned_req = req.try_clone();
        let response = next.run(req, extensions).await?;

        if (response.status() == reqwest::StatusCode::FOUND
            || response.status() == reqwest::StatusCode::TEMPORARY_REDIRECT)
            && let Some(mut retry_req) = cloned_req
            && let Some(cwm) = self.client_with_middleware.get()
        {
            tracing::debug!(
                hostname = %hostname,
                status = %response.status(),
                "3xx detected, acquiring cookie and retrying"
            );
            let _ = self.cookie_client.acquire_cookie(&hostname).await;
            let new_cookies = self.cookie_client.cookies(hostname.clone()).await;
            if !new_cookies.is_empty() {
                let cookie_header = new_cookies
                    .iter()
                    .map(|(name, value)| format!("{}={}", name, value))
                    .collect::<Vec<_>>()
                    .join("; ");
                if let Ok(header_value) = cookie_header.parse() {
                    retry_req.headers_mut().insert(http::header::COOKIE, header_value);
                }
            }
            tracing::debug!(hostname = %hostname, "Retrying request with updated cookies");
            return Ok(cwm.execute(retry_req).await?);
        }

        Ok(response)
    }
}

/// Constructs a ServerCommunicationConfigMiddleware.
///
/// Returns (middleware_arc, lock) where lock must be filled with the
/// Arc<ClientWithMiddleware> after it is built (resolves circular construction).
pub fn create_middleware<R, P>(
    client: ServerCommunicationConfigClient<R, P>,
) -> (
    Arc<dyn reqwest_middleware::Middleware>,
    Arc<OnceLock<Arc<ClientWithMiddleware>>>,
)
where
    R: ServerCommunicationConfigRepository + Clone + Send + Sync + 'static,
    P: ServerCommunicationConfigPlatformApi + Clone + Send + Sync + 'static,
{
    let middleware = ServerCommunicationConfigMiddleware::new(Arc::new(client));
    let lock = middleware.client_with_middleware_lock();
    (Arc::new(middleware), lock)
}

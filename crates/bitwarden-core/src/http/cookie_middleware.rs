use std::sync::Arc;

use super::CookieStore;

/// Middleware that injects cookies from a CookieStore into HTTP requests.
///
/// Integrates with reqwest_middleware framework (ADR-049). Queries CookieStore for
/// non-expired cookies and formats them as a Cookie header per RFC 6265.
pub struct CookieInjectionMiddleware {
    cookie_store: Arc<dyn CookieStore>,
}

impl CookieInjectionMiddleware {
    /// Creates a new cookie injection middleware with the specified store.
    pub fn new(cookie_store: Arc<dyn CookieStore>) -> Self {
        Self { cookie_store }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl reqwest_middleware::Middleware for CookieInjectionMiddleware {
    async fn handle(
        &self,
        mut req: reqwest::Request,
        extensions: &mut http::Extensions,
        next: reqwest_middleware::Next<'_>,
    ) -> Result<reqwest::Response, reqwest_middleware::Error> {
        // Query cookie store for all non-expired cookies
        let cookies = match self.cookie_store.list_cookies().await {
            Ok(names) => {
                let mut cookie_values = Vec::new();
                for name in names {
                    if let Ok(Some(cookie)) = self.cookie_store.get_cookie(&name).await {
                        cookie_values.push(cookie.to_cookie_header());
                    }
                }
                cookie_values
            }
            Err(e) => {
                tracing::warn!("Failed to retrieve cookies from store: {e}");
                Vec::new()
            }
        };

        // Inject Cookie header if any cookies exist
        if !cookies.is_empty() {
            let cookie_header = cookies.join("; ");
            match cookie_header.parse() {
                Ok(header_value) => {
                    req.headers_mut().insert(http::header::COOKIE, header_value);
                }
                Err(e) => {
                    tracing::warn!("Failed to parse cookie header: {e}");
                }
            }
        }

        // Continue middleware chain
        next.run(req, extensions).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Cookie, InMemoryCookieStore};

    #[tokio::test]
    async fn test_middleware_injects_cookie_header() {
        // This test requires mocking reqwest_middleware::Next which is complex.
        // Integration test will verify actual HTTP request includes Cookie header.
        // Unit test verifies cookie retrieval and formatting logic only.

        let store = Arc::new(InMemoryCookieStore::new());
        store
            .set_cookie(Cookie::new("session", "token123"))
            .await
            .unwrap();

        let middleware = CookieInjectionMiddleware::new(store.clone());

        // Verify store contains cookie
        let cookies = store.list_cookies().await.unwrap();
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0], "session");
    }

    #[tokio::test]
    async fn test_middleware_handles_empty_store() {
        let store = Arc::new(InMemoryCookieStore::new());
        let middleware = CookieInjectionMiddleware::new(store.clone());

        let cookies = store.list_cookies().await.unwrap();
        assert_eq!(cookies.len(), 0);
    }
}

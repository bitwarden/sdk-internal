use std::sync::Arc;

use bitwarden_core::auth::CookieProvider;
use http::Extensions;
use reqwest::Request;
use reqwest_middleware::{Middleware, Next, Result as MiddlewareResult};
use tracing::debug;

/// Injects SSO load-balancer cookies into outbound HTTP requests.
/// On 3xx redirect, acquires fresh cookies and retries once (ADR-006).
pub struct ServerCommunicationConfigMiddleware {
    provider: Arc<dyn CookieProvider>,
}

impl ServerCommunicationConfigMiddleware {
    /// Creates a new middleware from a cookie provider.
    pub fn new(provider: Arc<dyn CookieProvider>) -> Self {
        Self { provider }
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
        // Clone BEFORE injection and first run — try_clone() fails for streaming bodies.
        let retry_req = req.try_clone();

        inject_cookies(&mut req, &*self.provider).await;

        let response = next.clone().run(req, extensions).await?;

        if response.status().is_redirection() {
            if let Some(mut retry) = retry_req {
                let hostname = retry.url().host_str().unwrap_or_default().to_string();
                if let Err(e) = self.provider.acquire_cookie(&hostname).await {
                    debug!("Cookie acquisition failed (suppressed): {e:?}");
                }
                inject_cookies(&mut retry, &*self.provider).await;
                return next.run(retry, extensions).await;
            }
        }

        Ok(response)
    }
}

pub(crate) async fn inject_cookies(req: &mut Request, provider: &dyn CookieProvider) {
    let hostname = req.url().host_str().unwrap_or_default().to_string();
    if hostname.is_empty() {
        return;
    }
    let cookies = provider.cookies(hostname).await;
    for (name, value) in cookies {
        let cookie_str = format!("{name}={value}");
        if let Ok(header_value) = reqwest::header::HeaderValue::from_str(&cookie_str) {
            req.headers_mut()
                .append(reqwest::header::COOKIE, header_value);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, RwLock},
    };

    use super::*;

    struct MockCookieProvider {
        cookies: RwLock<HashMap<String, Vec<(String, String)>>>,
    }

    impl MockCookieProvider {
        fn new(hostname: &str, cookies: Vec<(String, String)>) -> Self {
            let mut map = HashMap::new();
            map.insert(hostname.to_string(), cookies);
            Self {
                cookies: RwLock::new(map),
            }
        }
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    impl CookieProvider for MockCookieProvider {
        async fn cookies(&self, hostname: String) -> Vec<(String, String)> {
            self.cookies
                .read()
                .unwrap()
                .get(&hostname)
                .cloned()
                .unwrap_or_default()
        }

        async fn acquire_cookie(
            &self,
            _hostname: &str,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn inject_cookies_appends_headers() {
        let provider = MockCookieProvider::new(
            "vault.example.com",
            vec![(
                "AWSELBAuthSessionCookie".to_string(),
                "token123".to_string(),
            )],
        );
        let mut req = reqwest::Request::new(
            reqwest::Method::GET,
            "https://vault.example.com/api/data".parse().unwrap(),
        );
        inject_cookies(&mut req, &provider).await;
        let cookie_header = req.headers().get(reqwest::header::COOKIE).unwrap();
        assert_eq!(
            cookie_header.to_str().unwrap(),
            "AWSELBAuthSessionCookie=token123"
        );
    }

    #[tokio::test]
    async fn inject_cookies_no_cookies_noop() {
        let provider = MockCookieProvider::new("vault.example.com", vec![]);
        let mut req = reqwest::Request::new(
            reqwest::Method::GET,
            "https://vault.example.com/api/data".parse().unwrap(),
        );
        inject_cookies(&mut req, &provider).await;
        assert!(req.headers().get(reqwest::header::COOKIE).is_none());
    }

    #[tokio::test]
    async fn inject_cookies_multiple_shards() {
        let provider = MockCookieProvider::new(
            "vault.example.com",
            vec![
                (
                    "AWSELBAuthSessionCookie-0".to_string(),
                    "shard0".to_string(),
                ),
                (
                    "AWSELBAuthSessionCookie-1".to_string(),
                    "shard1".to_string(),
                ),
            ],
        );
        let mut req = reqwest::Request::new(
            reqwest::Method::GET,
            "https://vault.example.com/api/data".parse().unwrap(),
        );
        inject_cookies(&mut req, &provider).await;
        let cookie_headers: Vec<_> = req
            .headers()
            .get_all(reqwest::header::COOKIE)
            .iter()
            .collect();
        assert_eq!(cookie_headers.len(), 2);
    }
}

use std::sync::Arc;

use reqwest_middleware::reqwest;

use crate::{ServerCommunicationConfigClient, ServerCommunicationConfigPlatformApi, ServerCommunicationConfigRepository};

/// Middleware that injects stored SSO load-balancer cookies into the `Cookie` header
/// of each outgoing API request.
///
/// On 3xx redirect responses the middleware propagates the response unchanged —
/// cookie re-acquisition is the application layer's responsibility (ADR-006).
pub struct ServerCommunicationConfigMiddleware<R, P>
where
    R: ServerCommunicationConfigRepository + Send + Sync + 'static,
    P: ServerCommunicationConfigPlatformApi + Send + Sync + 'static,
{
    pub(crate) config_client: Arc<ServerCommunicationConfigClient<R, P>>,
}

impl<R, P> Clone for ServerCommunicationConfigMiddleware<R, P>
where
    R: ServerCommunicationConfigRepository + Send + Sync + 'static,
    P: ServerCommunicationConfigPlatformApi + Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        Self {
            config_client: Arc::clone(&self.config_client),
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<R, P> reqwest_middleware::Middleware for ServerCommunicationConfigMiddleware<R, P>
where
    R: ServerCommunicationConfigRepository + Send + Sync + 'static,
    P: ServerCommunicationConfigPlatformApi + Send + Sync + 'static,
{
    async fn handle(
        &self,
        mut req: reqwest::Request,
        extensions: &mut http::Extensions,
        next: reqwest_middleware::Next<'_>,
    ) -> reqwest_middleware::Result<reqwest::Response> {
        let hostname = req.url().host_str().unwrap_or_default().to_owned();
        let cookies = self.config_client.cookies(hostname).await;

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

        next.run(req, extensions).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use tokio::sync::RwLock;

    use crate::{
        AcquiredCookie, BootstrapConfig, ServerCommunicationConfig, ServerCommunicationConfigClient,
        ServerCommunicationConfigPlatformApi, ServerCommunicationConfigRepository,
        SsoCookieVendorConfig,
    };

    use super::ServerCommunicationConfigMiddleware;

    #[derive(Default, Clone)]
    struct MockRepository {
        storage: Arc<RwLock<HashMap<String, ServerCommunicationConfig>>>,
    }

    impl ServerCommunicationConfigRepository for MockRepository {
        type GetError = ();
        type SaveError = ();

        async fn get(
            &self,
            hostname: String,
        ) -> Result<Option<ServerCommunicationConfig>, ()> {
            Ok(self.storage.read().await.get(&hostname).cloned())
        }

        async fn save(
            &self,
            hostname: String,
            config: ServerCommunicationConfig,
        ) -> Result<(), ()> {
            self.storage.write().await.insert(hostname, config);
            Ok(())
        }
    }

    #[derive(Clone)]
    struct MockPlatformApi;

    #[async_trait::async_trait]
    impl ServerCommunicationConfigPlatformApi for MockPlatformApi {
        async fn acquire_cookies(&self, _hostname: String) -> Option<Vec<AcquiredCookie>> {
            None
        }
    }

    async fn make_client_with_cookies(
        hostname: &str,
        cookies: Vec<AcquiredCookie>,
    ) -> Arc<ServerCommunicationConfigClient<MockRepository, MockPlatformApi>> {
        let repo = MockRepository::default();
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: None,
                cookie_name: Some("AWSELBAuthSessionCookie".to_string()),
                cookie_domain: Some(hostname.to_string()),
                cookie_value: Some(cookies),
            }),
        };
        repo.save(hostname.to_string(), config).await.unwrap();
        Arc::new(ServerCommunicationConfigClient::new(repo, MockPlatformApi))
    }

    fn make_empty_client(
    ) -> Arc<ServerCommunicationConfigClient<MockRepository, MockPlatformApi>> {
        Arc::new(ServerCommunicationConfigClient::new(
            MockRepository::default(),
            MockPlatformApi,
        ))
    }

    #[tokio::test]
    async fn middleware_no_cookie_header_when_empty() {
        let client = make_empty_client();
        let middleware = ServerCommunicationConfigMiddleware { config_client: client };

        let req = reqwest::Request::new(
            reqwest::Method::GET,
            "https://vault.example.com/api/test".parse().unwrap(),
        );
        assert!(req.headers().get(http::header::COOKIE).is_none());

        let cookies = middleware
            .config_client
            .cookies("vault.example.com".to_string())
            .await;
        assert!(cookies.is_empty(), "Expected no cookies for unconfigured host");
    }

    #[tokio::test]
    async fn middleware_formats_single_cookie() {
        let client = make_client_with_cookies(
            "vault.example.com",
            vec![AcquiredCookie {
                name: "AWSELBAuthSessionCookie".to_string(),
                value: "singlevalue".to_string(),
            }],
        )
        .await;
        let cookies = client.cookies("vault.example.com".to_string()).await;
        let header = cookies
            .iter()
            .map(|(n, v)| format!("{}={}", n, v))
            .collect::<Vec<_>>()
            .join("; ");
        assert_eq!(header, "AWSELBAuthSessionCookie=singlevalue");
    }

    #[tokio::test]
    async fn middleware_formats_sharded_cookies_with_semicolons() {
        let client = make_client_with_cookies(
            "vault.example.com",
            vec![
                AcquiredCookie {
                    name: "AWSELBAuthSessionCookie-0".to_string(),
                    value: "shard0".to_string(),
                },
                AcquiredCookie {
                    name: "AWSELBAuthSessionCookie-1".to_string(),
                    value: "shard1".to_string(),
                },
                AcquiredCookie {
                    name: "AWSELBAuthSessionCookie-2".to_string(),
                    value: "shard2".to_string(),
                },
            ],
        )
        .await;
        let cookies = client.cookies("vault.example.com".to_string()).await;
        let header = cookies
            .iter()
            .map(|(n, v)| format!("{}={}", n, v))
            .collect::<Vec<_>>()
            .join("; ");
        assert_eq!(
            header,
            "AWSELBAuthSessionCookie-0=shard0; AWSELBAuthSessionCookie-1=shard1; AWSELBAuthSessionCookie-2=shard2"
        );
    }

    #[tokio::test]
    async fn middleware_clone_shares_client() {
        let client = make_empty_client();
        let middleware = ServerCommunicationConfigMiddleware {
            config_client: Arc::clone(&client),
        };
        let cloned = middleware.clone();
        assert!(
            Arc::ptr_eq(&middleware.config_client, &cloned.config_client),
            "Clone should share the same Arc (no deep copy of client)"
        );
    }
}

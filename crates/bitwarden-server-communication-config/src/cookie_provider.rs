use crate::{
    AcquireCookieError, ServerCommunicationConfigClient, ServerCommunicationConfigPlatformApi,
    ServerCommunicationConfigRepository,
};

/// Abstraction for acquiring and retrieving SSO load balancer cookies.
///
/// Allows bitwarden-core to request cookies without depending on
/// bitwarden-server-communication-config. Middleware holds `Arc<dyn CookieProvider>`.
///
/// # Security
///
/// Implementors MUST NOT log cookie values. Cookie values are sensitive SSO tokens.
#[async_trait::async_trait]
pub trait CookieProvider: 'static + Send + Sync {
    /// Returns stored cookies for the given hostname as name-value pairs.
    ///
    /// Returns an empty vec when no cookies are stored for the hostname.
    async fn cookies(&self, hostname: &str) -> Vec<(String, String)>;

    /// Acquires a fresh cookie from the platform and stores it for the given hostname.
    ///
    /// Triggers the platform-specific SSO acquisition flow (e.g., WebView redirect).
    async fn acquire_cookie(&self, hostname: &str) -> Result<(), AcquireCookieError>;

    /// Returns true if the hostname requires SSO cookie bootstrapping.
    ///
    /// Returns false when no configuration exists for the hostname, or when
    /// the configuration is `Direct` (no cookie required). Middleware uses this
    /// to skip acquisition on redirects unrelated to SSO bootstrapping.
    async fn needs_bootstrap(&self, hostname: &str) -> bool;
}

#[async_trait::async_trait]
impl<R, P> CookieProvider for ServerCommunicationConfigClient<R, P>
where
    R: ServerCommunicationConfigRepository + Send + 'static,
    P: ServerCommunicationConfigPlatformApi + Send + 'static,
{
    async fn cookies(&self, hostname: &str) -> Vec<(String, String)> {
        self.cookies(hostname.to_string()).await
    }

    async fn acquire_cookie(&self, hostname: &str) -> Result<(), AcquireCookieError> {
        self.acquire_cookie(hostname).await
    }

    async fn needs_bootstrap(&self, hostname: &str) -> bool {
        self.needs_bootstrap(hostname.to_string()).await
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use tokio::sync::RwLock;

    use super::*;
    use crate::{
        AcquiredCookie, BootstrapConfig, ServerCommunicationConfig,
        ServerCommunicationConfigPlatformApi, ServerCommunicationConfigRepository,
        SsoCookieVendorConfig,
    };

    /// Mock in-memory repository for testing
    #[derive(Default, Clone)]
    struct MockRepository {
        storage: Arc<RwLock<HashMap<String, ServerCommunicationConfig>>>,
    }

    impl ServerCommunicationConfigRepository for MockRepository {
        type GetError = ();
        type SaveError = ();

        async fn get(&self, hostname: String) -> Result<Option<ServerCommunicationConfig>, ()> {
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

    /// Mock platform API for testing
    #[derive(Clone)]
    struct MockPlatformApi {
        cookies_to_return: Arc<RwLock<Option<Vec<AcquiredCookie>>>>,
    }

    impl MockPlatformApi {
        fn new() -> Self {
            Self {
                cookies_to_return: Arc::new(RwLock::new(None)),
            }
        }

        async fn set_cookies(&self, cookies: Option<Vec<AcquiredCookie>>) {
            *self.cookies_to_return.write().await = cookies;
        }
    }

    #[async_trait::async_trait]
    impl ServerCommunicationConfigPlatformApi for MockPlatformApi {
        async fn acquire_cookies(&self, _vault_url: String) -> Option<Vec<AcquiredCookie>> {
            self.cookies_to_return.read().await.clone()
        }
    }

    #[test]
    fn dyn_cookie_provider_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        fn check() {
            assert_send_sync::<Arc<dyn CookieProvider>>();
        }
        check();
    }

    #[tokio::test]
    async fn cookie_provider_cookies_delegates() {
        let repo = MockRepository::default();
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: Some("https://idp.example.com".to_string()),
                cookie_name: Some("TestCookie".to_string()),
                cookie_domain: Some("example.com".to_string()),
                vault_url: Some("https://vault.example.com".to_string()),
                cookie_value: Some(vec![AcquiredCookie {
                    name: "TestCookie".to_string(),
                    value: "test-value".to_string(),
                }]),
            }),
        };

        repo.save("vault.example.com".to_string(), config)
            .await
            .unwrap();

        let platform_api = MockPlatformApi::new();
        let client = ServerCommunicationConfigClient::new(repo, platform_api);
        let provider: &dyn CookieProvider = &client;

        let cookies = provider.cookies("vault.example.com").await;
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].0, "TestCookie");
        assert_eq!(cookies[0].1, "test-value");
    }

    #[tokio::test]
    async fn cookie_provider_acquire_cookie_delegates() {
        let repo = MockRepository::default();
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: Some("https://idp.example.com".to_string()),
                cookie_name: Some("TestCookie".to_string()),
                cookie_domain: Some("example.com".to_string()),
                vault_url: Some("https://vault.example.com".to_string()),
                cookie_value: None,
            }),
        };

        repo.save("vault.example.com".to_string(), config)
            .await
            .unwrap();

        let platform_api = MockPlatformApi::new();
        platform_api
            .set_cookies(Some(vec![AcquiredCookie {
                name: "TestCookie".to_string(),
                value: "acquired-value".to_string(),
            }]))
            .await;

        let client = ServerCommunicationConfigClient::new(repo, platform_api);
        let provider: &dyn CookieProvider = &client;

        let result = provider.acquire_cookie("vault.example.com").await;
        assert_eq!(result, Ok(()));
    }
}

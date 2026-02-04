#[cfg(test)]
use crate::AcquiredCookie;
use crate::{
    AcquireCookieError, BootstrapConfig, ServerCommunicationConfig,
    ServerCommunicationConfigPlatformApi, ServerCommunicationConfigRepository,
};

/// Server communication configuration client
pub struct ServerCommunicationConfigClient<R, P>
where
    R: ServerCommunicationConfigRepository,
    P: ServerCommunicationConfigPlatformApi,
{
    repository: R,
    platform_api: P,
}

impl<R, P> ServerCommunicationConfigClient<R, P>
where
    R: ServerCommunicationConfigRepository,
    P: ServerCommunicationConfigPlatformApi,
{
    /// Creates a new server communication configuration client
    ///
    /// # Arguments
    ///
    /// * `repository` - Cookie storage implementation (e.g a StateProvider hook)
    /// * `platform_api` - Cookie acquistion implementation
    pub fn new(repository: R, platform_api: P) -> Self {
        Self {
            repository,
            platform_api,
        }
    }

    /// Retrieves the server communication configuration for a hostname
    pub async fn get_config(
        &self,
        hostname: String,
    ) -> Result<ServerCommunicationConfig, R::GetError> {
        Ok(self
            .repository
            .get(hostname)
            .await?
            .unwrap_or(ServerCommunicationConfig {
                bootstrap: BootstrapConfig::Direct,
            }))
    }

    /// Determines if cookie bootstrapping is needed for this hostname
    pub async fn needs_bootstrap(&self, hostname: String) -> bool {
        if let Ok(Some(config)) = self.repository.get(hostname).await {
            if let BootstrapConfig::SsoCookieVendor(vendor_config) = config.bootstrap {
                return vendor_config.cookie_value.is_none();
            }
        }
        false
    }

    /// Returns cookies to include in HTTP requests
    pub async fn cookies(&self, hostname: String) -> Vec<(String, String)> {
        if let Ok(Some(config)) = self.repository.get(hostname).await {
            if let BootstrapConfig::SsoCookieVendor(vendor_config) = config.bootstrap {
                if let Some(cookie_value_shards) = vendor_config.cookie_value {
                    // Concatenate all cookie shards into a single value
                    let cookie_value = cookie_value_shards.join("");
                    return vec![(vendor_config.cookie_name, cookie_value)];
                }
            }
        }
        Vec::new()
    }

    /// Acquires a cookie from the platform and saves it to the repository
    ///
    /// This method calls the platform API to trigger cookie acquisition (e.g., browser
    /// redirect to IdP), then validates and stores the acquired cookie in the repository.
    ///
    /// # Arguments
    ///
    /// * `hostname` - The server hostname (e.g., "vault.acme.com")
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Cookie acquisition was cancelled by the user ([`AcquireCookieError::Cancelled`])
    /// - Server configuration doesn't support SSO cookies
    ///   ([`AcquireCookieError::UnsupportedConfiguration`])
    /// - Acquired cookie name doesn't match expected name
    ///   ([`AcquireCookieError::CookieNameMismatch`])
    /// - Repository operations fail ([`AcquireCookieError::RepositoryGetError`] or
    ///   [`AcquireCookieError::RepositorySaveError`])
    pub async fn acquire_cookie(&self, hostname: &str) -> Result<(), AcquireCookieError> {
        // Get existing configuration - we need this to know what cookie to expect
        let mut config = self
            .repository
            .get(hostname.to_string())
            .await
            .map_err(|e| AcquireCookieError::RepositoryGetError(format!("{:?}", e)))?
            .ok_or(AcquireCookieError::UnsupportedConfiguration)?;

        // Verify this is an SSO cookie vendor configuration and get mutable reference
        let BootstrapConfig::SsoCookieVendor(ref mut vendor_config) = config.bootstrap else {
            return Err(AcquireCookieError::UnsupportedConfiguration);
        };

        let expected_cookie_name = &vendor_config.cookie_name;

        // Call platform API to acquire the cookie
        let cookie = self
            .platform_api
            .acquire_cookie(hostname.to_string())
            .await
            .ok_or(AcquireCookieError::Cancelled)?;

        // Validate the cookie name matches what we expect
        if cookie.name != *expected_cookie_name {
            return Err(AcquireCookieError::CookieNameMismatch {
                expected: expected_cookie_name.clone(),
                actual: cookie.name,
            });
        }

        // Update the cookie value using the mutable reference we already have
        vendor_config.cookie_value = Some(cookie.value);

        // Save the updated config
        self.repository
            .save(hostname.to_string(), config)
            .await
            .map_err(|e| AcquireCookieError::RepositorySaveError(format!("{:?}", e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use tokio::sync::RwLock;

    use super::*;
    use crate::SsoCookieVendorConfig;

    /// Mock in-memory repository for testing
    #[derive(Default, Clone)]
    struct MockRepository {
        storage: std::sync::Arc<RwLock<HashMap<String, ServerCommunicationConfig>>>,
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
        cookie_to_return: std::sync::Arc<RwLock<Option<AcquiredCookie>>>,
    }

    impl MockPlatformApi {
        fn new() -> Self {
            Self {
                cookie_to_return: std::sync::Arc::new(RwLock::new(None)),
            }
        }

        async fn set_cookie(&self, cookie: Option<AcquiredCookie>) {
            *self.cookie_to_return.write().await = cookie;
        }
    }

    #[async_trait::async_trait]
    impl ServerCommunicationConfigPlatformApi for MockPlatformApi {
        async fn acquire_cookie(&self, _hostname: String) -> Option<AcquiredCookie> {
            self.cookie_to_return.read().await.clone()
        }
    }

    #[tokio::test]
    async fn get_config_returns_direct_when_not_found() {
        let repo = MockRepository::default();
        let platform_api = MockPlatformApi::new();
        let client = ServerCommunicationConfigClient::new(repo, platform_api);

        let config = client
            .get_config("vault.example.com".to_string())
            .await
            .unwrap();

        assert!(matches!(config.bootstrap, BootstrapConfig::Direct));
    }

    #[tokio::test]
    async fn get_config_returns_saved_config() {
        let repo = MockRepository::default();
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: "https://example.com".to_string(),
                cookie_name: "TestCookie".to_string(),
                cookie_domain: "example.com".to_string(),
                cookie_value: Some(vec!["value123".to_string()]),
            }),
        };

        repo.save("vault.example.com".to_string(), config.clone())
            .await
            .unwrap();

        let platform_api = MockPlatformApi::new();
        let client = ServerCommunicationConfigClient::new(repo.clone(), platform_api);
        let retrieved = client
            .get_config("vault.example.com".to_string())
            .await
            .unwrap();

        assert!(matches!(
            retrieved.bootstrap,
            BootstrapConfig::SsoCookieVendor(_)
        ));
    }

    #[tokio::test]
    async fn needs_bootstrap_true_when_cookie_missing() {
        let repo = MockRepository::default();
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: "https://example.com".to_string(),
                cookie_name: "TestCookie".to_string(),
                cookie_domain: "example.com".to_string(),
                cookie_value: None,
            }),
        };

        repo.save("vault.example.com".to_string(), config)
            .await
            .unwrap();

        let platform_api = MockPlatformApi::new();
        let client = ServerCommunicationConfigClient::new(repo.clone(), platform_api);
        assert!(
            client
                .needs_bootstrap("vault.example.com".to_string())
                .await
        );
    }

    #[tokio::test]
    async fn needs_bootstrap_false_when_cookie_present() {
        let repo = MockRepository::default();
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: "https://example.com".to_string(),
                cookie_name: "TestCookie".to_string(),
                cookie_domain: "example.com".to_string(),
                cookie_value: Some(vec!["value123".to_string()]),
            }),
        };

        repo.save("vault.example.com".to_string(), config)
            .await
            .unwrap();

        let platform_api = MockPlatformApi::new();
        let client = ServerCommunicationConfigClient::new(repo.clone(), platform_api);
        assert!(
            !client
                .needs_bootstrap("vault.example.com".to_string())
                .await
        );
    }

    #[tokio::test]
    async fn needs_bootstrap_false_for_direct() {
        let repo = MockRepository::default();
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::Direct,
        };

        repo.save("vault.example.com".to_string(), config)
            .await
            .unwrap();

        let platform_api = MockPlatformApi::new();
        let client = ServerCommunicationConfigClient::new(repo.clone(), platform_api);
        assert!(
            !client
                .needs_bootstrap("vault.example.com".to_string())
                .await
        );
    }

    #[tokio::test]
    async fn cookies_returns_empty_for_direct() {
        let repo = MockRepository::default();
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::Direct,
        };

        repo.save("vault.example.com".to_string(), config)
            .await
            .unwrap();

        let platform_api = MockPlatformApi::new();
        let client = ServerCommunicationConfigClient::new(repo.clone(), platform_api);
        let cookies = client.cookies("vault.example.com".to_string()).await;

        assert!(cookies.is_empty());
    }

    #[tokio::test]
    async fn cookies_returns_empty_when_value_none() {
        let repo = MockRepository::default();
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: "https://example.com".to_string(),
                cookie_name: "TestCookie".to_string(),
                cookie_domain: "example.com".to_string(),
                cookie_value: None,
            }),
        };

        repo.save("vault.example.com".to_string(), config)
            .await
            .unwrap();

        let platform_api = MockPlatformApi::new();
        let client = ServerCommunicationConfigClient::new(repo.clone(), platform_api);
        let cookies = client.cookies("vault.example.com".to_string()).await;

        assert!(cookies.is_empty());
    }

    #[tokio::test]
    async fn cookies_returns_cookie_when_present() {
        let repo = MockRepository::default();
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: "https://example.com".to_string(),
                cookie_name: "AELBAuthSessionCookie".to_string(),
                cookie_domain: "example.com".to_string(),
                cookie_value: Some(vec!["eyJhbGciOiJFUzI1NiIsImtpZCI6Im...".to_string()]),
            }),
        };

        repo.save("vault.example.com".to_string(), config)
            .await
            .unwrap();

        let platform_api = MockPlatformApi::new();
        let client = ServerCommunicationConfigClient::new(repo.clone(), platform_api);
        let cookies = client.cookies("vault.example.com".to_string()).await;

        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].0, "AELBAuthSessionCookie");
        assert_eq!(cookies[0].1, "eyJhbGciOiJFUzI1NiIsImtpZCI6Im...");
    }

    #[tokio::test]
    async fn cookies_returns_empty_when_no_config() {
        let repo = MockRepository::default();
        let platform_api = MockPlatformApi::new();
        let client = ServerCommunicationConfigClient::new(repo, platform_api);
        let cookies = client.cookies("vault.example.com".to_string()).await;

        assert!(cookies.is_empty());
    }

    #[tokio::test]
    async fn cookies_concatenates_shards() {
        let repo = MockRepository::default();
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: "https://example.com".to_string(),
                cookie_name: "ShardedCookie".to_string(),
                cookie_domain: "example.com".to_string(),
                cookie_value: Some(vec![
                    "shard1".to_string(),
                    "shard2".to_string(),
                    "shard3".to_string(),
                ]),
            }),
        };

        repo.save("vault.example.com".to_string(), config)
            .await
            .unwrap();

        let platform_api = MockPlatformApi::new();
        let client = ServerCommunicationConfigClient::new(repo, platform_api);
        let cookies = client.cookies("vault.example.com".to_string()).await;

        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].0, "ShardedCookie");
        // Verify shards are concatenated
        assert_eq!(cookies[0].1, "shard1shard2shard3");
    }

    #[tokio::test]
    async fn acquire_cookie_saves_when_cookie_returned() {
        let repo = MockRepository::default();
        let platform_api = MockPlatformApi::new();

        // Setup existing config with SsoCookieVendor
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: "https://example.com".to_string(),
                cookie_name: "TestCookie".to_string(),
                cookie_domain: "example.com".to_string(),
                cookie_value: None,
            }),
        };
        repo.save("vault.example.com".to_string(), config)
            .await
            .unwrap();

        // Configure platform API to return a cookie with correct name
        platform_api
            .set_cookie(Some(AcquiredCookie {
                name: "TestCookie".to_string(),
                value: vec!["acquired-cookie-value".to_string()],
            }))
            .await;

        let client = ServerCommunicationConfigClient::new(repo.clone(), platform_api);

        // Call acquire_cookie - should succeed
        client.acquire_cookie("vault.example.com").await.unwrap();

        // Verify cookie was saved
        let saved_config = repo
            .get("vault.example.com".to_string())
            .await
            .unwrap()
            .unwrap();

        if let BootstrapConfig::SsoCookieVendor(vendor_config) = saved_config.bootstrap {
            assert_eq!(
                vendor_config.cookie_value,
                Some(vec!["acquired-cookie-value".to_string()])
            );
        } else {
            panic!("Expected SsoCookieVendor config");
        }
    }

    #[tokio::test]
    async fn acquire_cookie_returns_cancelled_when_none() {
        let repo = MockRepository::default();
        let platform_api = MockPlatformApi::new();

        // Setup existing config
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: "https://example.com".to_string(),
                cookie_name: "TestCookie".to_string(),
                cookie_domain: "example.com".to_string(),
                cookie_value: None,
            }),
        };
        repo.save("vault.example.com".to_string(), config)
            .await
            .unwrap();

        // Platform API returns None (user cancelled)
        platform_api.set_cookie(None).await;

        let client = ServerCommunicationConfigClient::new(repo, platform_api);

        let result = client.acquire_cookie("vault.example.com").await;

        assert!(matches!(result, Err(AcquireCookieError::Cancelled)));
    }

    #[tokio::test]
    async fn acquire_cookie_returns_unsupported_for_direct_config() {
        let repo = MockRepository::default();
        let platform_api = MockPlatformApi::new();

        // Setup Direct config
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::Direct,
        };
        repo.save("vault.example.com".to_string(), config)
            .await
            .unwrap();

        // Platform API returns a cookie
        platform_api
            .set_cookie(Some(AcquiredCookie {
                name: "TestCookie".to_string(),
                value: vec!["cookie-value".to_string()],
            }))
            .await;

        let client = ServerCommunicationConfigClient::new(repo, platform_api);

        let result = client.acquire_cookie("vault.example.com").await;

        // Should return UnsupportedConfiguration because config is Direct
        assert!(matches!(
            result,
            Err(AcquireCookieError::UnsupportedConfiguration)
        ));
    }

    #[tokio::test]
    async fn acquire_cookie_validates_cookie_name() {
        let repo = MockRepository::default();
        let platform_api = MockPlatformApi::new();

        // Setup config expecting "ExpectedCookie"
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: "https://example.com".to_string(),
                cookie_name: "ExpectedCookie".to_string(),
                cookie_domain: "example.com".to_string(),
                cookie_value: None,
            }),
        };
        repo.save("vault.example.com".to_string(), config)
            .await
            .unwrap();

        // Platform API returns wrong cookie name
        platform_api
            .set_cookie(Some(AcquiredCookie {
                name: "WrongCookie".to_string(),
                value: vec!["some-value".to_string()],
            }))
            .await;

        let client = ServerCommunicationConfigClient::new(repo, platform_api);

        let result = client.acquire_cookie("vault.example.com").await;

        // Should return CookieNameMismatch
        match result {
            Err(AcquireCookieError::CookieNameMismatch { expected, actual }) => {
                assert_eq!(expected, "ExpectedCookie");
                assert_eq!(actual, "WrongCookie");
            }
            _ => panic!("Expected CookieNameMismatch error"),
        }
    }

    #[tokio::test]
    async fn acquire_cookie_returns_unsupported_when_no_config() {
        let repo = MockRepository::default();
        let platform_api = MockPlatformApi::new();

        // No config saved for this hostname

        let client = ServerCommunicationConfigClient::new(repo, platform_api);

        let result = client.acquire_cookie("vault.example.com").await;

        // Should return UnsupportedConfiguration because no config exists
        assert!(matches!(
            result,
            Err(AcquireCookieError::UnsupportedConfiguration)
        ));
    }
}

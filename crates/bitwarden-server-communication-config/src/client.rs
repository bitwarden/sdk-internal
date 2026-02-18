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
    ///
    /// Returns the stored cookies as-is. For sharded cookies, each entry includes
    /// the full cookie name with its `-{N}` suffix (e.g., `AWSELBAuthSessionCookie-0`).
    pub async fn cookies(&self, hostname: String) -> Vec<(String, String)> {
        if let Ok(Some(config)) = self.repository.get(hostname).await {
            if let BootstrapConfig::SsoCookieVendor(vendor_config) = config.bootstrap {
                if let Some(acquired_cookies) = vendor_config.cookie_value {
                    return acquired_cookies
                        .into_iter()
                        .map(|cookie| (cookie.name, cookie.value))
                        .collect();
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

        let expected_cookie_name = vendor_config
            .cookie_name
            .as_ref()
            .ok_or(AcquireCookieError::UnsupportedConfiguration)?;

        // Call platform API to acquire cookies
        let cookies = self
            .platform_api
            .acquire_cookies(hostname.to_string())
            .await
            .ok_or(AcquireCookieError::Cancelled)?;

        // Validate that all cookies match the expected base name
        // Cookie names should either:
        // 1. Exactly match the expected name (unsharded cookie)
        // 2. Match the pattern {expected_name}-{N} where N is a digit (sharded cookies)
        //
        // AWS ALB shards cookies > 4KB with naming pattern: {base_name}-{N}
        // where N starts at 0 (e.g., AWSELBAuthSessionCookie-0, AWSELBAuthSessionCookie-1)
        let all_cookies_match = cookies.iter().all(|cookie| {
            cookie.name == *expected_cookie_name
                || cookie
                    .name
                    .strip_prefix(&format!("{}-", expected_cookie_name))
                    .is_some_and(|suffix| suffix.chars().all(|c| c.is_ascii_digit()))
        });

        if !all_cookies_match {
            // Find the first mismatched cookie for error reporting
            let mismatched = cookies
                .iter()
                .find(|cookie| {
                    cookie.name != *expected_cookie_name
                        && !cookie
                            .name
                            .strip_prefix(&format!("{}-", expected_cookie_name))
                            .is_some_and(|suffix| suffix.chars().all(|c| c.is_ascii_digit()))
                })
                .expect("all_cookies_match is false, so at least one cookie must not match");

            return Err(AcquireCookieError::CookieNameMismatch {
                expected: expected_cookie_name.clone(),
                actual: mismatched.name.clone(),
            });
        }

        // Update the cookie values using the mutable reference we already have
        vendor_config.cookie_value = Some(cookies);

        // Save the updated config
        self.repository
            .save(hostname.to_string(), config)
            .await
            .map_err(|e| AcquireCookieError::RepositorySaveError(format!("{:?}", e)))?;

        Ok(())
    }
}

// CookieProvider trait implementation for type erasure (ADR-006)
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<R, P> crate::CookieProvider for ServerCommunicationConfigClient<R, P>
where
    R: ServerCommunicationConfigRepository + Send + Sync + 'static,
    P: ServerCommunicationConfigPlatformApi + Send + Sync + 'static,
{
    async fn cookies(&self, hostname: String) -> Vec<(String, String)> {
        // Inline implementation to satisfy Send bounds
        // (delegating to self.cookies() creates non-Send future on some platforms)
        if let Ok(Some(config)) = self.repository.get(hostname).await {
            if let BootstrapConfig::SsoCookieVendor(vendor_config) = config.bootstrap {
                if let Some(acquired_cookies) = vendor_config.cookie_value {
                    return acquired_cookies
                        .into_iter()
                        .map(|cookie| (cookie.name, cookie.value))
                        .collect();
                }
            }
        }
        Vec::new()
    }

    async fn acquire_cookie(
        &self,
        hostname: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Delegate to the existing acquire_cookie method
        // Convert AcquireCookieError to boxed trait object
        self.acquire_cookie(hostname)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
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
        cookies_to_return: std::sync::Arc<RwLock<Option<Vec<AcquiredCookie>>>>,
    }

    impl MockPlatformApi {
        fn new() -> Self {
            Self {
                cookies_to_return: std::sync::Arc::new(RwLock::new(None)),
            }
        }

        async fn set_cookies(&self, cookies: Option<Vec<AcquiredCookie>>) {
            *self.cookies_to_return.write().await = cookies;
        }
    }

    #[async_trait::async_trait]
    impl ServerCommunicationConfigPlatformApi for MockPlatformApi {
        async fn acquire_cookies(&self, _hostname: String) -> Option<Vec<AcquiredCookie>> {
            self.cookies_to_return.read().await.clone()
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
                idp_login_url: Some("https://example.com".to_string()),
                cookie_name: Some("TestCookie".to_string()),
                cookie_domain: Some("example.com".to_string()),
                cookie_value: Some(vec![AcquiredCookie {
                    name: "TestCookie".to_string(),
                    value: "value123".to_string(),
                }]),
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
                idp_login_url: Some("https://example.com".to_string()),
                cookie_name: Some("TestCookie".to_string()),
                cookie_domain: Some("example.com".to_string()),
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
                idp_login_url: Some("https://example.com".to_string()),
                cookie_name: Some("TestCookie".to_string()),
                cookie_domain: Some("example.com".to_string()),
                cookie_value: Some(vec![AcquiredCookie {
                    name: "TestCookie".to_string(),
                    value: "value123".to_string(),
                }]),
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
                idp_login_url: Some("https://example.com".to_string()),
                cookie_name: Some("TestCookie".to_string()),
                cookie_domain: Some("example.com".to_string()),
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
    async fn cookies_returns_unsharded_cookie_without_suffix() {
        let repo = MockRepository::default();
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: Some("https://example.com".to_string()),
                cookie_name: Some("AWSELBAuthSessionCookie".to_string()),
                cookie_domain: Some("example.com".to_string()),
                cookie_value: Some(vec![AcquiredCookie {
                    name: "AWSELBAuthSessionCookie".to_string(),
                    value: "eyJhbGciOiJFUzI1NiIsImtpZCI6Im...".to_string(),
                }]),
            }),
        };

        repo.save("vault.example.com".to_string(), config)
            .await
            .unwrap();

        let platform_api = MockPlatformApi::new();
        let client = ServerCommunicationConfigClient::new(repo.clone(), platform_api);
        let cookies = client.cookies("vault.example.com".to_string()).await;

        // Single cookie without suffix
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].0, "AWSELBAuthSessionCookie");
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
    async fn cookies_returns_shards_with_numbered_suffixes() {
        let repo = MockRepository::default();
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: Some("https://example.com".to_string()),
                cookie_name: Some("AWSELBAuthSessionCookie".to_string()),
                cookie_domain: Some("example.com".to_string()),
                cookie_value: Some(vec![
                    AcquiredCookie {
                        name: "AWSELBAuthSessionCookie-0".to_string(),
                        value: "shard0value".to_string(),
                    },
                    AcquiredCookie {
                        name: "AWSELBAuthSessionCookie-1".to_string(),
                        value: "shard1value".to_string(),
                    },
                    AcquiredCookie {
                        name: "AWSELBAuthSessionCookie-2".to_string(),
                        value: "shard2value".to_string(),
                    },
                ]),
            }),
        };

        repo.save("vault.example.com".to_string(), config)
            .await
            .unwrap();

        let platform_api = MockPlatformApi::new();
        let client = ServerCommunicationConfigClient::new(repo, platform_api);
        let cookies = client.cookies("vault.example.com".to_string()).await;

        // Each shard is returned as stored with -N suffix
        assert_eq!(cookies.len(), 3);
        assert_eq!(
            cookies[0],
            (
                "AWSELBAuthSessionCookie-0".to_string(),
                "shard0value".to_string()
            )
        );
        assert_eq!(
            cookies[1],
            (
                "AWSELBAuthSessionCookie-1".to_string(),
                "shard1value".to_string()
            )
        );
        assert_eq!(
            cookies[2],
            (
                "AWSELBAuthSessionCookie-2".to_string(),
                "shard2value".to_string()
            )
        );
    }

    #[tokio::test]
    async fn acquire_cookie_saves_when_cookie_returned() {
        let repo = MockRepository::default();
        let platform_api = MockPlatformApi::new();

        // Setup existing config with SsoCookieVendor
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: Some("https://example.com".to_string()),
                cookie_name: Some("TestCookie".to_string()),
                cookie_domain: Some("example.com".to_string()),
                cookie_value: None,
            }),
        };
        repo.save("vault.example.com".to_string(), config)
            .await
            .unwrap();

        // Configure platform API to return a cookie with correct name
        platform_api
            .set_cookies(Some(vec![AcquiredCookie {
                name: "TestCookie".to_string(),
                value: "acquired-cookie-value".to_string(),
            }]))
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
            assert_eq!(vendor_config.cookie_value.as_ref().unwrap().len(), 1);
            assert_eq!(
                vendor_config.cookie_value.as_ref().unwrap()[0].name,
                "TestCookie"
            );
            assert_eq!(
                vendor_config.cookie_value.as_ref().unwrap()[0].value,
                "acquired-cookie-value"
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
                idp_login_url: Some("https://example.com".to_string()),
                cookie_name: Some("TestCookie".to_string()),
                cookie_domain: Some("example.com".to_string()),
                cookie_value: None,
            }),
        };
        repo.save("vault.example.com".to_string(), config)
            .await
            .unwrap();

        // Platform API returns None (user cancelled)
        platform_api.set_cookies(None).await;

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
            .set_cookies(Some(vec![AcquiredCookie {
                name: "TestCookie".to_string(),
                value: "cookie-value".to_string(),
            }]))
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
                idp_login_url: Some("https://example.com".to_string()),
                cookie_name: Some("ExpectedCookie".to_string()),
                cookie_domain: Some("example.com".to_string()),
                cookie_value: None,
            }),
        };
        repo.save("vault.example.com".to_string(), config)
            .await
            .unwrap();

        // Platform API returns wrong cookie name
        platform_api
            .set_cookies(Some(vec![AcquiredCookie {
                name: "WrongCookie".to_string(),
                value: "some-value".to_string(),
            }]))
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

    #[tokio::test]
    async fn acquire_cookie_accepts_sharded_cookies_with_numbered_suffixes() {
        let repo = MockRepository::default();
        let platform_api = MockPlatformApi::new();

        // Setup config expecting "AWSELBAuthSessionCookie"
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: Some("https://example.com".to_string()),
                cookie_name: Some("AWSELBAuthSessionCookie".to_string()),
                cookie_domain: Some("example.com".to_string()),
                cookie_value: None,
            }),
        };
        repo.save("vault.example.com".to_string(), config)
            .await
            .unwrap();

        // Platform API returns multiple shards with -N suffixes
        platform_api
            .set_cookies(Some(vec![
                AcquiredCookie {
                    name: "AWSELBAuthSessionCookie-0".to_string(),
                    value: "shard0value".to_string(),
                },
                AcquiredCookie {
                    name: "AWSELBAuthSessionCookie-1".to_string(),
                    value: "shard1value".to_string(),
                },
                AcquiredCookie {
                    name: "AWSELBAuthSessionCookie-2".to_string(),
                    value: "shard2value".to_string(),
                },
            ]))
            .await;

        let client = ServerCommunicationConfigClient::new(repo.clone(), platform_api);

        // Should succeed
        client.acquire_cookie("vault.example.com").await.unwrap();

        // Verify all shards were saved
        let saved_config = repo
            .get("vault.example.com".to_string())
            .await
            .unwrap()
            .unwrap();

        if let BootstrapConfig::SsoCookieVendor(vendor_config) = saved_config.bootstrap {
            assert_eq!(vendor_config.cookie_value.as_ref().unwrap().len(), 3);
            assert_eq!(
                vendor_config.cookie_value.as_ref().unwrap()[0].name,
                "AWSELBAuthSessionCookie-0"
            );
            assert_eq!(
                vendor_config.cookie_value.as_ref().unwrap()[1].name,
                "AWSELBAuthSessionCookie-1"
            );
            assert_eq!(
                vendor_config.cookie_value.as_ref().unwrap()[2].name,
                "AWSELBAuthSessionCookie-2"
            );
        } else {
            panic!("Expected SsoCookieVendor config");
        }
    }

    #[tokio::test]
    async fn acquire_cookie_accepts_unsharded_cookie_without_suffix() {
        let repo = MockRepository::default();
        let platform_api = MockPlatformApi::new();

        // Setup config
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: Some("https://example.com".to_string()),
                cookie_name: Some("SessionCookie".to_string()),
                cookie_domain: Some("example.com".to_string()),
                cookie_value: None,
            }),
        };
        repo.save("vault.example.com".to_string(), config)
            .await
            .unwrap();

        // Platform API returns single cookie without suffix
        platform_api
            .set_cookies(Some(vec![AcquiredCookie {
                name: "SessionCookie".to_string(),
                value: "single-cookie-value".to_string(),
            }]))
            .await;

        let client = ServerCommunicationConfigClient::new(repo.clone(), platform_api);

        // Should succeed
        client.acquire_cookie("vault.example.com").await.unwrap();

        // Verify value was saved
        let saved_config = repo
            .get("vault.example.com".to_string())
            .await
            .unwrap()
            .unwrap();

        if let BootstrapConfig::SsoCookieVendor(vendor_config) = saved_config.bootstrap {
            assert_eq!(vendor_config.cookie_value.as_ref().unwrap().len(), 1);
            assert_eq!(
                vendor_config.cookie_value.as_ref().unwrap()[0].name,
                "SessionCookie"
            );
            assert_eq!(
                vendor_config.cookie_value.as_ref().unwrap()[0].value,
                "single-cookie-value"
            );
        } else {
            panic!("Expected SsoCookieVendor config");
        }
    }
}

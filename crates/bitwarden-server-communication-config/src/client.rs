use crate::{
    AcquireCookieError, AcquiredCookie, BootstrapConfig, BootstrapConfigRequest,
    ServerCommunicationConfig, ServerCommunicationConfigPlatformApi,
    ServerCommunicationConfigRepository, SetCommunicationTypeRequest, SsoCookieVendorConfig,
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

    /// Retrieves the server communication configuration for a domain
    pub async fn get_config(
        &self,
        domain: String,
    ) -> Result<ServerCommunicationConfig, R::GetError> {
        Ok(self
            .repository
            .get(domain)
            .await?
            .unwrap_or(ServerCommunicationConfig {
                bootstrap: BootstrapConfig::Direct,
            }))
    }

    /// Returns whether this domain uses cookie bootstrapping
    ///
    /// Returns `true` if the domain has an `SsoCookieVendor` configuration,
    /// regardless of whether cookies have already been acquired. This is useful
    /// for determining if the domain requires the bootstrap flow (e.g., to show
    /// appropriate UI), without making claims about cookie validity.
    pub async fn needs_bootstrap(&self, domain: String) -> bool {
        if let Ok(Some(config)) = self.repository.get(domain).await {
            return matches!(config.bootstrap, BootstrapConfig::SsoCookieVendor(_));
        }
        false
    }

    /// Returns cookies to include in HTTP requests
    ///
    /// Returns the stored cookies as-is. For sharded cookies, each entry includes
    /// the full cookie name with its `-{N}` suffix (e.g., `AWSELBAuthSessionCookie-0`).
    #[deprecated(
        note = "Use get_cookies() instead, which will acquire cookies if not present in the config"
    )]
    pub async fn cookies(&self, domain: String) -> Vec<(String, String)> {
        if let Ok(Some(config)) = self.repository.get(domain).await
            && let BootstrapConfig::SsoCookieVendor(vendor_config) = config.bootstrap
            && let Some(acquired_cookies) = vendor_config.cookie_value
        {
            return acquired_cookies
                .into_iter()
                .map(|cookie| (cookie.name, cookie.value))
                .collect();
        }
        Vec::new()
    }

    /// Returns cookies to include in HTTP requests. For sharded cookies, each entry includes
    /// the full cookie name with its `-{N}` suffix (e.g., `AWSELBAuthSessionCookie-0`).
    ///
    /// - If the configuration is not found or is Direct, returns an empty vector.
    /// - If the configuration is SsoCookieVendor but has no acquired cookies, it will acquire them
    ///   using the platform API and return the acquired cookies.
    pub async fn get_cookies(
        &self,
        domain: String,
    ) -> Result<Vec<AcquiredCookie>, AcquireCookieError> {
        let config = self
            .repository
            .get(domain.clone())
            .await
            .map_err(|e| AcquireCookieError::RepositoryGetError(format!("{:?}", e)))?;

        let Some(config) = config else {
            return Ok(vec![]);
        };

        let BootstrapConfig::SsoCookieVendor(vendor_config) = config.bootstrap else {
            return Ok(vec![]);
        };

        match vendor_config.cookie_value {
            Some(ref cookies) => Ok(cookies.clone()),
            None => Ok(self.acquire_cookie(&domain).await?),
        }
    }

    /// Sets the server communication configuration for a domain
    ///
    /// This method saves the provided communication configuration to the repository.
    /// Typically called when receiving the `/api/config` response from the server.
    ///
    /// The request type intentionally excludes `cookie_value`, since cookies are
    /// managed separately via [`Self::acquire_cookie`]. Any previously acquired
    /// cookies stored in the repository are preserved across calls to this method.
    ///
    /// # Arguments
    ///
    /// * `domain` - The server domain (e.g., "vault.acme.com")
    /// * `request` - The server communication configuration to store
    ///
    /// # Errors
    ///
    /// Returns an error if the repository save operation fails
    #[deprecated(
        note = "Use set_communication_type_v2() instead, which extracts the domain from the config"
    )]
    pub async fn set_communication_type(
        &self,
        domain: String,
        request: SetCommunicationTypeRequest,
    ) -> Result<(), R::SaveError> {
        let existing_cookie_value = match &request.bootstrap {
            BootstrapConfigRequest::SsoCookieVendor(_) => self
                .repository
                .get(domain.clone())
                .await
                .ok()
                .flatten()
                .and_then(|existing| match existing.bootstrap {
                    BootstrapConfig::SsoCookieVendor(v) => v.cookie_value,
                    _ => None,
                }),
            BootstrapConfigRequest::Direct => None,
        };

        let config = ServerCommunicationConfig {
            bootstrap: match request.bootstrap {
                BootstrapConfigRequest::Direct => BootstrapConfig::Direct,
                BootstrapConfigRequest::SsoCookieVendor(v) => {
                    BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                        idp_login_url: v.idp_login_url,
                        cookie_name: v.cookie_name,
                        cookie_domain: v.cookie_domain,
                        vault_url: v.vault_url,
                        cookie_value: existing_cookie_value,
                    })
                }
            },
        };

        self.repository.save(domain, config).await
    }

    /// Sets the server communication configuration using the domain from the config itself
    ///
    /// Extracts the `cookie_domain` from the `SsoCookieVendor` config and uses it as the
    /// storage key. If the config is `Direct` or the `cookie_domain` is not set, the call
    /// is silently ignored.
    ///
    /// Typically called when receiving the `/api/config` response from the server.
    ///
    /// # Arguments
    ///
    /// * `config` - The server communication configuration to store
    ///
    /// # Errors
    ///
    /// Returns an error if the repository save operation fails
    pub async fn set_communication_type_v2(
        &self,
        config: ServerCommunicationConfig,
    ) -> Result<(), R::SaveError> {
        if let BootstrapConfig::SsoCookieVendor(ref vendor_config) = config.bootstrap
            && let Some(ref domain) = vendor_config.cookie_domain
        {
            self.repository.save(domain.clone(), config).await?;
        }
        Ok(())
    }

    /// Acquires a cookie from the platform and saves it to the repository
    ///
    /// This method calls the platform API to trigger cookie acquisition (e.g., browser
    /// redirect to IdP), then validates and stores the acquired cookie in the repository.
    ///
    /// # Arguments
    ///
    /// * `domain` - The server domain (e.g., "vault.acme.com")
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
    pub async fn acquire_cookie(
        &self,
        domain: &str,
    ) -> Result<Vec<AcquiredCookie>, AcquireCookieError> {
        // Get existing configuration - we need this to know what cookie to expect
        let mut config = self
            .repository
            .get(domain.to_string())
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

        // Extract vault_url from vendor_config
        let vault_url = vendor_config
            .vault_url
            .as_ref()
            .filter(|s| !s.is_empty())
            .ok_or(AcquireCookieError::UnsupportedConfiguration)?
            .clone();

        // Call platform API to acquire cookies, passing vault_url
        let cookies = self
            .platform_api
            .acquire_cookies(vault_url)
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
        vendor_config.cookie_value = Some(cookies.clone());

        // Save the updated config
        self.repository
            .save(domain.to_string(), config)
            .await
            .map_err(|e| AcquireCookieError::RepositorySaveError(format!("{:?}", e)))?;

        Ok(cookies)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use tokio::sync::RwLock;

    use super::*;
    use crate::{SsoCookieVendorConfig, SsoCookieVendorConfigRequest};

    /// Mock in-memory repository for testing
    #[derive(Default, Clone)]
    struct MockRepository {
        storage: std::sync::Arc<RwLock<HashMap<String, ServerCommunicationConfig>>>,
    }

    impl ServerCommunicationConfigRepository for MockRepository {
        type GetError = ();
        type SaveError = ();

        async fn get(&self, domain: String) -> Result<Option<ServerCommunicationConfig>, ()> {
            Ok(self.storage.read().await.get(&domain).cloned())
        }

        async fn save(&self, domain: String, config: ServerCommunicationConfig) -> Result<(), ()> {
            self.storage.write().await.insert(domain, config);
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
        async fn acquire_cookies(&self, _vault_url: String) -> Option<Vec<AcquiredCookie>> {
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
                vault_url: Some("https://vault.example.com".to_string()),
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
    async fn needs_bootstrap_true_for_sso_cookie_vendor() {
        let repo = MockRepository::default();
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: Some("https://example.com".to_string()),
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
        let client = ServerCommunicationConfigClient::new(repo.clone(), platform_api);
        assert!(
            client
                .needs_bootstrap("vault.example.com".to_string())
                .await
        );
    }

    #[tokio::test]
    async fn needs_bootstrap_true_when_cookie_already_present() {
        let repo = MockRepository::default();
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: Some("https://example.com".to_string()),
                cookie_name: Some("TestCookie".to_string()),
                cookie_domain: Some("example.com".to_string()),
                vault_url: Some("https://vault.example.com".to_string()),
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
            client
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
                vault_url: Some("https://vault.example.com".to_string()),
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
                vault_url: Some("https://vault.example.com".to_string()),
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
                vault_url: Some("https://vault.example.com".to_string()),
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
                vault_url: Some("https://vault.example.com".to_string()),
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
                vault_url: Some("https://vault.example.com".to_string()),
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
                vault_url: Some("https://vault.example.com".to_string()),
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

        // No config saved for this domain

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
                vault_url: Some("https://vault.example.com".to_string()),
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
                vault_url: Some("https://vault.example.com".to_string()),
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

    #[tokio::test]
    async fn get_cookies_returns_empty_for_direct() {
        let repo = MockRepository::default();
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::Direct,
        };

        repo.save("vault.example.com".to_string(), config)
            .await
            .unwrap();

        let platform_api = MockPlatformApi::new();
        let client = ServerCommunicationConfigClient::new(repo, platform_api);
        let cookies = client
            .get_cookies("vault.example.com".to_string())
            .await
            .unwrap();

        assert!(cookies.is_empty());
    }

    #[tokio::test]
    async fn get_cookies_returns_empty_when_no_config() {
        let repo = MockRepository::default();
        let platform_api = MockPlatformApi::new();
        let client = ServerCommunicationConfigClient::new(repo, platform_api);
        let cookies = client
            .get_cookies("vault.example.com".to_string())
            .await
            .unwrap();

        assert!(cookies.is_empty());
    }

    #[tokio::test]
    async fn get_cookies_returns_existing_cookies() {
        let repo = MockRepository::default();
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: Some("https://example.com".to_string()),
                cookie_name: Some("TestCookie".to_string()),
                cookie_domain: Some("example.com".to_string()),
                cookie_value: Some(vec![AcquiredCookie {
                    name: "TestCookie".to_string(),
                    value: "existing-value".to_string(),
                }]),
            }),
        };

        repo.save("vault.example.com".to_string(), config)
            .await
            .unwrap();

        let platform_api = MockPlatformApi::new();
        let client = ServerCommunicationConfigClient::new(repo, platform_api);
        let cookies = client
            .get_cookies("vault.example.com".to_string())
            .await
            .unwrap();

        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].name, "TestCookie");
        assert_eq!(cookies[0].value, "existing-value");
    }

    #[tokio::test]
    async fn get_cookies_acquires_when_none_present() {
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
        platform_api
            .set_cookies(Some(vec![AcquiredCookie {
                name: "TestCookie".to_string(),
                value: "acquired-value".to_string(),
            }]))
            .await;

        let client = ServerCommunicationConfigClient::new(repo.clone(), platform_api);
        let cookies = client
            .get_cookies("vault.example.com".to_string())
            .await
            .unwrap();

        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].name, "TestCookie");
        assert_eq!(cookies[0].value, "acquired-value");

        // Verify cookies were also saved to repo
        let saved_config = repo
            .get("vault.example.com".to_string())
            .await
            .unwrap()
            .unwrap();

        if let BootstrapConfig::SsoCookieVendor(vendor_config) = saved_config.bootstrap {
            assert_eq!(vendor_config.cookie_value.as_ref().unwrap().len(), 1);
            assert_eq!(
                vendor_config.cookie_value.as_ref().unwrap()[0].value,
                "acquired-value"
            );
        } else {
            panic!("Expected SsoCookieVendor config");
        }
    }

    #[tokio::test]
    async fn get_cookies_returns_cancelled_when_acquisition_fails() {
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

        // Platform API returns None (user cancelled)
        let platform_api = MockPlatformApi::new();
        platform_api.set_cookies(None).await;

        let client = ServerCommunicationConfigClient::new(repo, platform_api);
        let result = client.get_cookies("vault.example.com".to_string()).await;

        assert!(matches!(result, Err(AcquireCookieError::Cancelled)));
    }

    #[tokio::test]
    async fn get_cookies_returns_existing_sharded_cookies() {
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
                ]),
            }),
        };

        repo.save("vault.example.com".to_string(), config)
            .await
            .unwrap();

        let platform_api = MockPlatformApi::new();
        let client = ServerCommunicationConfigClient::new(repo, platform_api);
        let cookies = client
            .get_cookies("vault.example.com".to_string())
            .await
            .unwrap();

        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[0].name, "AWSELBAuthSessionCookie-0");
        assert_eq!(cookies[1].name, "AWSELBAuthSessionCookie-1");
    }

    #[tokio::test]
    #[allow(deprecated)]
    async fn set_communication_type_saves_direct_config() {
        let repo = MockRepository::default();
        let platform_api = MockPlatformApi::new();
        let client = ServerCommunicationConfigClient::new(repo.clone(), platform_api);

        let request = SetCommunicationTypeRequest {
            bootstrap: BootstrapConfigRequest::Direct,
        };

        client
            .set_communication_type("vault.example.com".to_string(), request)
            .await
            .unwrap();

        let saved_config = repo
            .get("vault.example.com".to_string())
            .await
            .unwrap()
            .unwrap();

        assert!(matches!(saved_config.bootstrap, BootstrapConfig::Direct));
    }

    #[tokio::test]
    #[allow(deprecated)]
    async fn set_communication_type_saves_sso_cookie_vendor_config() {
        let repo = MockRepository::default();
        let platform_api = MockPlatformApi::new();
        let client = ServerCommunicationConfigClient::new(repo.clone(), platform_api);

        let request = SetCommunicationTypeRequest {
            bootstrap: BootstrapConfigRequest::SsoCookieVendor(SsoCookieVendorConfigRequest {
                idp_login_url: Some("https://idp.example.com/login".to_string()),
                cookie_name: Some("SessionCookie".to_string()),
                cookie_domain: Some("vault.example.com".to_string()),
                vault_url: Some("https://vault.example.com".to_string()),
            }),
        };

        client
            .set_communication_type("vault.example.com".to_string(), request)
            .await
            .unwrap();

        let saved_config = repo
            .get("vault.example.com".to_string())
            .await
            .unwrap()
            .unwrap();

        if let BootstrapConfig::SsoCookieVendor(vendor_config) = saved_config.bootstrap {
            assert_eq!(
                vendor_config.idp_login_url,
                Some("https://idp.example.com/login".to_string())
            );
            assert_eq!(vendor_config.cookie_name, Some("SessionCookie".to_string()));
            assert_eq!(
                vendor_config.cookie_domain,
                Some("vault.example.com".to_string())
            );
            assert!(vendor_config.cookie_value.is_none());
        } else {
            panic!("Expected SsoCookieVendor config");
        }
    }

    #[tokio::test]
    #[allow(deprecated)]
    async fn set_communication_type_overwrites_existing_config() {
        let repo = MockRepository::default();
        let platform_api = MockPlatformApi::new();

        // Setup existing Direct config
        let old_config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::Direct,
        };
        repo.save("vault.example.com".to_string(), old_config)
            .await
            .unwrap();

        let client = ServerCommunicationConfigClient::new(repo.clone(), platform_api);

        // Overwrite with SsoCookieVendor config
        let request = SetCommunicationTypeRequest {
            bootstrap: BootstrapConfigRequest::SsoCookieVendor(SsoCookieVendorConfigRequest {
                idp_login_url: Some("https://new-idp.example.com/login".to_string()),
                cookie_name: Some("NewCookie".to_string()),
                cookie_domain: Some("vault.example.com".to_string()),
                vault_url: Some("https://vault.example.com".to_string()),
            }),
        };

        client
            .set_communication_type("vault.example.com".to_string(), request)
            .await
            .unwrap();

        let saved_config = repo
            .get("vault.example.com".to_string())
            .await
            .unwrap()
            .unwrap();

        if let BootstrapConfig::SsoCookieVendor(vendor_config) = saved_config.bootstrap {
            assert_eq!(
                vendor_config.idp_login_url,
                Some("https://new-idp.example.com/login".to_string())
            );
            assert_eq!(vendor_config.cookie_name, Some("NewCookie".to_string()));
        } else {
            panic!("Expected SsoCookieVendor config");
        }
    }

    #[tokio::test]
    #[allow(deprecated)]
    async fn set_communication_type_preserves_per_domain_isolation() {
        let repo = MockRepository::default();
        let platform_api = MockPlatformApi::new();
        let client = ServerCommunicationConfigClient::new(repo.clone(), platform_api);

        let request1 = SetCommunicationTypeRequest {
            bootstrap: BootstrapConfigRequest::Direct,
        };
        client
            .set_communication_type("vault1.example.com".to_string(), request1)
            .await
            .unwrap();

        let request2 = SetCommunicationTypeRequest {
            bootstrap: BootstrapConfigRequest::SsoCookieVendor(SsoCookieVendorConfigRequest {
                idp_login_url: Some("https://idp.example.com/login".to_string()),
                cookie_name: Some("TestCookie".to_string()),
                cookie_domain: Some("vault2.example.com".to_string()),
                vault_url: Some("https://vault2.example.com".to_string()),
            }),
        };
        client
            .set_communication_type("vault2.example.com".to_string(), request2)
            .await
            .unwrap();

        let saved_config1 = repo
            .get("vault1.example.com".to_string())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(saved_config1.bootstrap, BootstrapConfig::Direct));

        let saved_config2 = repo
            .get("vault2.example.com".to_string())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            saved_config2.bootstrap,
            BootstrapConfig::SsoCookieVendor(_)
        ));
    }

    #[tokio::test]
    async fn set_communication_type_preserves_existing_cookies() {
        let repo = MockRepository::default();
        let platform_api = MockPlatformApi::new();

        // Setup existing config with acquired cookies
        let existing_config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: Some("https://idp.example.com/login".to_string()),
                cookie_name: Some("SessionCookie".to_string()),
                cookie_domain: Some("example.com".to_string()),
                vault_url: Some("https://vault.example.com".to_string()),
                cookie_value: Some(vec![AcquiredCookie {
                    name: "SessionCookie".to_string(),
                    value: "previously-acquired-value".to_string(),
                }]),
            }),
        };
        repo.save("vault.example.com".to_string(), existing_config)
            .await
            .unwrap();

        let client = ServerCommunicationConfigClient::new(repo.clone(), platform_api);

        // Re-emit the same config (as happens during auth state transitions)
        let request = SetCommunicationTypeRequest {
            bootstrap: BootstrapConfigRequest::SsoCookieVendor(SsoCookieVendorConfigRequest {
                idp_login_url: Some("https://idp.example.com/login".to_string()),
                cookie_name: Some("SessionCookie".to_string()),
                cookie_domain: Some("example.com".to_string()),
                vault_url: Some("https://vault.example.com".to_string()),
            }),
        };

        client
            .set_communication_type("vault.example.com".to_string(), request)
            .await
            .unwrap();

        // Verify cookies were preserved
        let saved_config = repo
            .get("vault.example.com".to_string())
            .await
            .unwrap()
            .unwrap();

        if let BootstrapConfig::SsoCookieVendor(vendor_config) = saved_config.bootstrap {
            let cookies = vendor_config
                .cookie_value
                .expect("cookies should be preserved");
            assert_eq!(cookies.len(), 1);
            assert_eq!(cookies[0].name, "SessionCookie");
            assert_eq!(cookies[0].value, "previously-acquired-value");
        } else {
            panic!("Expected SsoCookieVendor config");
        }
    }

    #[tokio::test]
    async fn set_communication_type_v2_saves_using_cookie_domain() {
        let repo = MockRepository::default();
        let platform_api = MockPlatformApi::new();
        let client = ServerCommunicationConfigClient::new(repo.clone(), platform_api);

        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: Some("https://idp.example.com/login".to_string()),
                cookie_name: Some("SessionCookie".to_string()),
                cookie_domain: Some("vault.example.com".to_string()),
                vault_url: None,
                cookie_value: None,
            }),
        };

        client.set_communication_type_v2(config).await.unwrap();

        // Verify config was saved under the cookie_domain key
        let saved_config = repo
            .get("vault.example.com".to_string())
            .await
            .unwrap()
            .unwrap();

        if let BootstrapConfig::SsoCookieVendor(vendor_config) = saved_config.bootstrap {
            assert_eq!(
                vendor_config.idp_login_url,
                Some("https://idp.example.com/login".to_string())
            );
            assert_eq!(vendor_config.cookie_name, Some("SessionCookie".to_string()));
        } else {
            panic!("Expected SsoCookieVendor config");
        }
    }

    #[tokio::test]
    async fn acquire_cookie_returns_unsupported_when_vault_url_none() {
        let repo = MockRepository::default();
        let platform_api = MockPlatformApi::new();

        // Setup config with SsoCookieVendor but vault_url is None
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: Some("https://example.com".to_string()),
                cookie_name: Some("TestCookie".to_string()),
                cookie_domain: Some("example.com".to_string()),
                vault_url: None, // Missing vault_url
                cookie_value: None,
            }),
        };
        repo.save("vault.example.com".to_string(), config)
            .await
            .unwrap();

        // Platform API is ready to return cookies (but shouldn't be called)
        platform_api
            .set_cookies(Some(vec![AcquiredCookie {
                name: "TestCookie".to_string(),
                value: "value".to_string(),
            }]))
            .await;

        let client = ServerCommunicationConfigClient::new(repo, platform_api);

        let result = client.acquire_cookie("vault.example.com").await;

        // Should return UnsupportedConfiguration because vault_url is None
        assert!(matches!(
            result,
            Err(AcquireCookieError::UnsupportedConfiguration)
        ));
    }

    #[tokio::test]
    async fn acquire_cookie_returns_unsupported_when_vault_url_empty() {
        let repo = MockRepository::default();
        let platform_api = MockPlatformApi::new();

        // Setup config with SsoCookieVendor but vault_url is empty string
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: Some("https://example.com".to_string()),
                cookie_name: Some("TestCookie".to_string()),
                cookie_domain: Some("example.com".to_string()),
                vault_url: Some("".to_string()), // Empty vault_url
                cookie_value: None,
            }),
        };
        repo.save("vault.example.com".to_string(), config)
            .await
            .unwrap();

        // Platform API is ready to return cookies (but shouldn't be called)
        platform_api
            .set_cookies(Some(vec![AcquiredCookie {
                name: "TestCookie".to_string(),
                value: "value".to_string(),
            }]))
            .await;

        let client = ServerCommunicationConfigClient::new(repo, platform_api);

        let result = client.acquire_cookie("vault.example.com").await;

        // Should return UnsupportedConfiguration because vault_url is empty
        assert!(matches!(
            result,
            Err(AcquireCookieError::UnsupportedConfiguration)
        ));
    }

    #[tokio::test]
    async fn set_communication_type_v2_ignores_direct_config() {
        let repo = MockRepository::default();
        let platform_api = MockPlatformApi::new();
        let client = ServerCommunicationConfigClient::new(repo.clone(), platform_api);

        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::Direct,
        };

        client.set_communication_type_v2(config).await.unwrap();

        // Verify nothing was saved
        assert!(repo.storage.read().await.is_empty());
    }

    #[tokio::test]
    async fn set_communication_type_v2_ignores_missing_cookie_domain() {
        let repo = MockRepository::default();
        let platform_api = MockPlatformApi::new();
        let client = ServerCommunicationConfigClient::new(repo.clone(), platform_api);

        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: Some("https://idp.example.com/login".to_string()),
                cookie_name: Some("SessionCookie".to_string()),
                cookie_domain: None,
                vault_url: None,
                cookie_value: None,
            }),
        };

        client.set_communication_type_v2(config).await.unwrap();

        // Verify nothing was saved
        assert!(repo.storage.read().await.is_empty());
    }
}

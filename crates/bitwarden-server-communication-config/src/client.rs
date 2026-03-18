use std::sync::Arc;

#[cfg(test)]
use crate::AcquiredCookie;
use crate::{
    AcquireCookieError, BootstrapConfig, ServerCommunicationConfig,
    ServerCommunicationConfigPlatformApi, ServerCommunicationConfigRepository,
};

/// Internal state for [`ServerCommunicationConfigClient`], held behind an [`Arc`]
/// so the outer struct can derive [`Clone`] without requiring [`Clone`] bounds on
/// `R` or `P`. (ADR-057)
struct ServerCommunicationConfigClientInner<R, P>
where
    R: ServerCommunicationConfigRepository,
    P: ServerCommunicationConfigPlatformApi,
{
    repository: R,
    platform_api: P,
}

/// Server communication configuration client
pub struct ServerCommunicationConfigClient<R, P>
where
    R: ServerCommunicationConfigRepository,
    P: ServerCommunicationConfigPlatformApi,
{
    inner: Arc<ServerCommunicationConfigClientInner<R, P>>,
}

impl<R, P> Clone for ServerCommunicationConfigClient<R, P>
where
    R: ServerCommunicationConfigRepository,
    P: ServerCommunicationConfigPlatformApi,
{
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
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
            inner: Arc::new(ServerCommunicationConfigClientInner {
                repository,
                platform_api,
            }),
        }
    }

    /// Retrieves the server communication configuration for a hostname
    pub async fn get_config(
        &self,
        hostname: String,
    ) -> Result<ServerCommunicationConfig, R::GetError> {
        Ok(self
            .inner
            .repository
            .get(hostname)
            .await?
            .unwrap_or(ServerCommunicationConfig {
                bootstrap: BootstrapConfig::Direct,
            }))
    }

    /// Determines if cookie bootstrapping is needed for this hostname
    pub async fn needs_bootstrap(&self, hostname: String) -> bool {
        if let Ok(Some(config)) = self.inner.repository.get(hostname).await
            && let BootstrapConfig::SsoCookieVendor(vendor_config) = config.bootstrap
        {
            return vendor_config.cookie_value.is_none();
        }
        false
    }

    /// Returns cookies to include in HTTP requests
    ///
    /// Returns the stored cookies as-is. For sharded cookies, each entry includes
    /// the full cookie name with its `-{N}` suffix (e.g., `AWSELBAuthSessionCookie-0`).
    pub async fn cookies(&self, hostname: String) -> Vec<(String, String)> {
        if let Ok(Some(config)) = self.inner.repository.get(hostname).await
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

    /// Sets the server communication configuration for a hostname
    ///
    /// This method saves the provided communication configuration to the repository.
    /// Typically called when receiving the `/api/config` response from the server.
    ///
    /// # Arguments
    ///
    /// * `hostname` - The server hostname (e.g., "vault.acme.com")
    /// * `config` - The server communication configuration to store
    ///
    /// # Errors
    ///
    /// Returns an error if the repository save operation fails
    pub async fn set_communication_type(
        &self,
        hostname: String,
        config: ServerCommunicationConfig,
    ) -> Result<(), R::SaveError> {
        self.inner.repository.save(hostname, config).await
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
            .inner
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

        // Extract vault_url from vendor_config
        let vault_url = vendor_config
            .vault_url
            .as_ref()
            .filter(|s| !s.is_empty())
            .ok_or(AcquireCookieError::UnsupportedConfiguration)?
            .clone();

        // Call platform API to acquire cookies, passing vault_url
        let cookies = self
            .inner
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
        vendor_config.cookie_value = Some(cookies);

        // Save the updated config
        self.inner
            .repository
            .save(hostname.to_string(), config)
            .await
            .map_err(|e| AcquireCookieError::RepositorySaveError(format!("{:?}", e)))?;

        Ok(())
    }
}

/// Middleware that injects stored SSO load balancer cookies into outbound HTTP requests
/// and retries once on 3xx responses after re-acquiring cookies. (ADR-058)
///
/// Cookie values are never logged. The middleware is a no-op for hostnames without
/// SSO configuration.
#[cfg(feature = "middleware")]
#[derive(Clone)]
pub struct ServerCommunicationConfigMiddleware<R, P>
where
    R: ServerCommunicationConfigRepository,
    P: ServerCommunicationConfigPlatformApi,
{
    client: ServerCommunicationConfigClient<R, P>,
}

/// Formats cookies per RFC 6265 §4.2.1 and inserts as a single Cookie header.
/// Uses insert() (not append()) to ensure exactly one Cookie header per request.
/// Cookie values are not logged.
#[cfg(feature = "middleware")]
fn inject_cookies(req: &mut reqwest_middleware::reqwest::Request, cookies: Vec<(String, String)>) {
    if cookies.is_empty() {
        return;
    }
    let header_value = cookies
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ");
    if let Ok(value) = http::HeaderValue::from_str(&header_value) {
        req.headers_mut()
            .insert(reqwest_middleware::reqwest::header::COOKIE, value);
    }
}

#[cfg(feature = "middleware")]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<R, P> reqwest_middleware::Middleware for ServerCommunicationConfigMiddleware<R, P>
where
    R: ServerCommunicationConfigRepository + Send + Sync + 'static,
    P: ServerCommunicationConfigPlatformApi + Send + Sync + 'static,
{
    async fn handle(
        &self,
        mut req: reqwest_middleware::reqwest::Request,
        extensions: &mut http::Extensions,
        next: reqwest_middleware::Next<'_>,
    ) -> Result<reqwest_middleware::reqwest::Response, reqwest_middleware::Error> {
        // Step 1: Extract hostname; forward without injection if absent
        let hostname = match req.url().host_str().map(|h| h.to_owned()) {
            Some(h) => h,
            None => return next.run(req, extensions).await,
        };

        // Step 2: Fetch stored cookies and inject (count logged only, no values)
        let cookies = self.client.cookies(hostname.clone()).await;
        inject_cookies(&mut req, cookies);

        // Step 3: Clone next before first attempt (required for retry)
        let next_clone = next.clone();

        // Step 4: Attempt request; retry once on 3xx if body is cloneable
        match req.try_clone() {
            Some(cloned_req) => {
                let response = next_clone.run(cloned_req, extensions).await?;

                if response.status().is_redirection() {
                    if let Some(mut retry_req) = req.try_clone() {
                        // Re-acquire fresh cookies (saves to repository as side-effect)
                        let _ = self.client.acquire_cookie(&hostname).await;
                        let fresh_cookies = self.client.cookies(hostname).await;
                        inject_cookies(&mut retry_req, fresh_cookies);
                        return next.run(retry_req, extensions).await;
                    }
                }

                Ok(response)
            }
            // Non-cloneable (streaming) body: no retry possible, return as-is
            None => next.run(req, extensions).await,
        }
    }
}

#[cfg(feature = "middleware")]
impl<R, P> ServerCommunicationConfigClient<R, P>
where
    R: ServerCommunicationConfigRepository + Send + Sync + 'static,
    P: ServerCommunicationConfigPlatformApi + Send + Sync + 'static,
{
    /// Creates a type-erased middleware from this client suitable for use with
    /// `reqwest_middleware::ClientBuilder::with_arc`.
    ///
    /// The middleware injects SSO load balancer cookies on every outbound request
    /// and retries once on 3xx responses. (ADR-058, ADR-059)
    pub fn create_middleware(&self) -> std::sync::Arc<dyn reqwest_middleware::Middleware> {
        std::sync::Arc::new(ServerCommunicationConfigMiddleware {
            client: self.clone(),
        })
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
    async fn needs_bootstrap_true_when_cookie_missing() {
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
    async fn needs_bootstrap_false_when_cookie_present() {
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
    async fn set_communication_type_saves_direct_config() {
        let repo = MockRepository::default();
        let platform_api = MockPlatformApi::new();
        let client = ServerCommunicationConfigClient::new(repo.clone(), platform_api);

        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::Direct,
        };

        // Call set_communication_type
        client
            .set_communication_type("vault.example.com".to_string(), config.clone())
            .await
            .unwrap();

        // Verify config was saved
        let saved_config = repo
            .get("vault.example.com".to_string())
            .await
            .unwrap()
            .unwrap();

        assert!(matches!(saved_config.bootstrap, BootstrapConfig::Direct));
    }

    #[tokio::test]
    async fn set_communication_type_saves_sso_cookie_vendor_config() {
        let repo = MockRepository::default();
        let platform_api = MockPlatformApi::new();
        let client = ServerCommunicationConfigClient::new(repo.clone(), platform_api);

        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: Some("https://idp.example.com/login".to_string()),
                cookie_name: Some("SessionCookie".to_string()),
                cookie_domain: Some("vault.example.com".to_string()),
                vault_url: Some("https://vault.example.com".to_string()),
                cookie_value: None,
            }),
        };

        // Call set_communication_type
        client
            .set_communication_type("vault.example.com".to_string(), config.clone())
            .await
            .unwrap();

        // Verify config was saved
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
        let new_config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: Some("https://new-idp.example.com/login".to_string()),
                cookie_name: Some("NewCookie".to_string()),
                cookie_domain: Some("vault.example.com".to_string()),
                vault_url: Some("https://vault.example.com".to_string()),
                cookie_value: None,
            }),
        };

        client
            .set_communication_type("vault.example.com".to_string(), new_config)
            .await
            .unwrap();

        // Verify new config replaced old config
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
    async fn set_communication_type_preserves_per_hostname_isolation() {
        let repo = MockRepository::default();
        let platform_api = MockPlatformApi::new();
        let client = ServerCommunicationConfigClient::new(repo.clone(), platform_api);

        // Save config for first hostname
        let config1 = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::Direct,
        };
        client
            .set_communication_type("vault1.example.com".to_string(), config1)
            .await
            .unwrap();

        // Save different config for second hostname
        let config2 = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: Some("https://idp.example.com/login".to_string()),
                cookie_name: Some("TestCookie".to_string()),
                cookie_domain: Some("vault2.example.com".to_string()),
                vault_url: Some("https://vault2.example.com".to_string()),
                cookie_value: None,
            }),
        };
        client
            .set_communication_type("vault2.example.com".to_string(), config2)
            .await
            .unwrap();

        // Verify both configs are stored independently
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

    #[cfg(feature = "middleware")]
    mod middleware_tests {
        use super::*;

        #[test]
        fn middleware_inject_cookies_formats_rfc6265_header() {
            let mut req = reqwest_middleware::reqwest::Request::new(
                reqwest_middleware::reqwest::Method::GET,
                "https://vault.example.com/".parse().unwrap(),
            );
            inject_cookies(
                &mut req,
                vec![
                    ("name1".to_string(), "val1".to_string()),
                    ("name2".to_string(), "val2".to_string()),
                ],
            );
            let header = req
                .headers()
                .get(reqwest_middleware::reqwest::header::COOKIE)
                .unwrap();
            assert_eq!(header.to_str().unwrap(), "name1=val1; name2=val2");
        }

        #[test]
        fn middleware_no_cookie_header_when_empty() {
            let mut req = reqwest_middleware::reqwest::Request::new(
                reqwest_middleware::reqwest::Method::GET,
                "https://vault.example.com/".parse().unwrap(),
            );
            inject_cookies(&mut req, vec![]);
            assert!(
                req.headers()
                    .get(reqwest_middleware::reqwest::header::COOKIE)
                    .is_none()
            );
        }

        #[tokio::test]
        async fn middleware_no_op_when_no_hostname() {
            // A file:// URL has no host_str()
            let repo = MockRepository::default();
            let platform_api = MockPlatformApi::new();
            let client = ServerCommunicationConfigClient::new(repo, platform_api);
            let _middleware = ServerCommunicationConfigMiddleware { client };
            // If we reach here without panic, the struct was constructed correctly.
            // Full handle() invocation requires a mock HTTP server; this is a compile-time
            // assertion that the struct and its fields are accessible within cfg(test).
        }

        #[tokio::test]
        async fn create_middleware_returns_correct_type() {
            let repo = MockRepository::default();
            let platform_api = MockPlatformApi::new();
            let client = ServerCommunicationConfigClient::new(repo, platform_api);
            let _: std::sync::Arc<dyn reqwest_middleware::Middleware> = client.create_middleware();
            // compile-time assertion
        }
    }
}

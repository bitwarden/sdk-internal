use crate::{BootstrapConfig, ServerCommunicationConfig, ServerCommunicationConfigRepository};

/// Server communication configuration client
pub struct ServerCommunicationConfigClient<R>
where
    R: ServerCommunicationConfigRepository,
{
    repository: R,
}

impl<R> ServerCommunicationConfigClient<R>
where
    R: ServerCommunicationConfigRepository,
{
    /// Creates a new server communication configuration client
    ///
    /// # Arguments
    ///
    /// * `repository` - Repository implementation for storing configuration
    pub fn new(repository: R) -> Self {
        Self { repository }
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
                if let Some(cookie_value) = vendor_config.cookie_value {
                    return vec![(vendor_config.cookie_name, cookie_value)];
                }
            }
        }
        Vec::new()
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

    #[tokio::test]
    async fn get_config_returns_direct_when_not_found() {
        let repo = MockRepository::default();
        let client = ServerCommunicationConfigClient::new(repo);

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
                cookie_value: Some("value123".to_string()),
            }),
        };

        repo.save("vault.example.com".to_string(), config.clone())
            .await
            .unwrap();

        let client = ServerCommunicationConfigClient::new(repo.clone());
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

        let client = ServerCommunicationConfigClient::new(repo.clone());
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
                cookie_value: Some("value123".to_string()),
            }),
        };

        repo.save("vault.example.com".to_string(), config)
            .await
            .unwrap();

        let client = ServerCommunicationConfigClient::new(repo.clone());
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

        let client = ServerCommunicationConfigClient::new(repo.clone());
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

        let client = ServerCommunicationConfigClient::new(repo.clone());
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

        let client = ServerCommunicationConfigClient::new(repo.clone());
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
                cookie_value: Some("eyJhbGciOiJFUzI1NiIsImtpZCI6Im...".to_string()),
            }),
        };

        repo.save("vault.example.com".to_string(), config)
            .await
            .unwrap();

        let client = ServerCommunicationConfigClient::new(repo.clone());
        let cookies = client.cookies("vault.example.com".to_string()).await;

        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].0, "AELBAuthSessionCookie");
        assert_eq!(cookies[0].1, "eyJhbGciOiJFUzI1NiIsImtpZCI6Im...");
    }

    #[tokio::test]
    async fn cookies_returns_empty_when_no_config() {
        let repo = MockRepository::default();
        let client = ServerCommunicationConfigClient::new(repo);
        let cookies = client.cookies("vault.example.com".to_string()).await;

        assert!(cookies.is_empty());
    }
}

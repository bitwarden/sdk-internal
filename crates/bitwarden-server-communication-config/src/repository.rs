use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::ServerCommunicationConfig;

/// Repository errors for configuration storage operations
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[bitwarden_error(flat)]
pub enum ServerCommunicationConfigRepositoryError {
    /// Error occurred while retrieving configuration
    #[error("Failed to get configuration: {0}")]
    GetError(String),

    /// Error occurred while saving configuration
    #[error("Failed to save configuration: {0}")]
    SaveError(String),
}

/// Repository for storing server communication configuration
///
/// This trait abstracts storage to allow TypeScript implementations via State Provider
/// in WASM contexts, while also supporting in-memory implementations for testing.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait ServerCommunicationConfigRepository: Send + Sync {
    /// Error type returned by `get()` operations
    type GetError: std::fmt::Debug + Send + Sync + 'static;
    /// Error type returned by `save()` operations
    type SaveError: std::fmt::Debug + Send + Sync + 'static;

    /// Retrieves configuration for a hostname
    ///
    /// # Arguments
    ///
    /// * `hostname` - The server hostname (e.g., "vault.amazon.com")
    ///
    /// # Returns
    ///
    /// - `Ok(Some(config))` - Configuration exists for this hostname
    /// - `Ok(None)` - No configuration exists (not an error)
    /// - `Err(e)` - Storage operation failed
    async fn get(
        &self,
        hostname: String,
    ) -> Result<Option<ServerCommunicationConfig>, Self::GetError>;

    /// Saves configuration for a hostname
    ///
    /// Overwrites any existing configuration for this hostname.
    ///
    /// # Arguments
    ///
    /// * `hostname` - The server hostname (e.g., "vault.amazon.com")
    /// * `config` - The configuration to store
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Configuration saved successfully
    /// - `Err(e)` - Storage operation failed
    async fn save(
        &self,
        hostname: String,
        config: ServerCommunicationConfig,
    ) -> Result<(), Self::SaveError>;
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use tokio::sync::RwLock;

    use super::*;
    use crate::{BootstrapConfig, SsoCookieVendorConfig};

    /// In-memory implementation of the repository for testing
    #[derive(Default, Clone)]
    struct InMemoryRepository {
        storage: Arc<RwLock<HashMap<String, ServerCommunicationConfig>>>,
    }

    #[async_trait::async_trait]
    impl ServerCommunicationConfigRepository for InMemoryRepository {
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
    async fn repository_get_none() {
        let repo = InMemoryRepository::default();
        let result = repo.get("vault.example.com".to_string()).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn repository_save_and_get() {
        use crate::AcquiredCookie;

        let repo = InMemoryRepository::default();
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: Some("https://example.com/login".to_string()),
                cookie_name: Some("TestCookie".to_string()),
                cookie_domain: Some("example.com".to_string()),
                cookie_value: Some(vec![AcquiredCookie {
                    name: "TestCookie".to_string(),
                    value: "cookie-value-123".to_string(),
                }]),
            }),
        };

        // Save
        repo.save("vault.example.com".to_string(), config.clone())
            .await
            .unwrap();

        // Get
        let retrieved = repo
            .get("vault.example.com".to_string())
            .await
            .unwrap()
            .unwrap();

        if let BootstrapConfig::SsoCookieVendor(vendor_config) = retrieved.bootstrap {
            assert_eq!(vendor_config.cookie_name, Some("TestCookie".to_string()));
            assert_eq!(vendor_config.cookie_value.as_ref().unwrap().len(), 1);
            assert_eq!(
                vendor_config.cookie_value.as_ref().unwrap()[0].value,
                "cookie-value-123"
            );
        } else {
            panic!("Expected SsoCookieVendor");
        }
    }

    #[tokio::test]
    async fn repository_overwrite() {
        let repo = InMemoryRepository::default();

        // Save first config
        let config1 = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::Direct,
        };
        repo.save("vault.example.com".to_string(), config1)
            .await
            .unwrap();

        // Overwrite with second config
        let config2 = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: Some("https://example.com".to_string()),
                cookie_name: Some("Cookie".to_string()),
                cookie_domain: Some("example.com".to_string()),
                cookie_value: None,
            }),
        };
        repo.save("vault.example.com".to_string(), config2)
            .await
            .unwrap();

        // Verify second config is retrieved
        let retrieved = repo
            .get("vault.example.com".to_string())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            retrieved.bootstrap,
            BootstrapConfig::SsoCookieVendor(_)
        ));
    }

    #[tokio::test]
    async fn repository_multiple_hostnames() {
        let repo = InMemoryRepository::default();

        let config1 = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::Direct,
        };
        let config2 = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: Some("https://example.com".to_string()),
                cookie_name: Some("Cookie".to_string()),
                cookie_domain: Some("example.com".to_string()),
                cookie_value: None,
            }),
        };

        // Save different configs for different hostnames
        repo.save("vault1.example.com".to_string(), config1)
            .await
            .unwrap();
        repo.save("vault2.example.com".to_string(), config2)
            .await
            .unwrap();

        // Verify each hostname has its own config
        let retrieved1 = repo
            .get("vault1.example.com".to_string())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(retrieved1.bootstrap, BootstrapConfig::Direct));

        let retrieved2 = repo
            .get("vault2.example.com".to_string())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            retrieved2.bootstrap,
            BootstrapConfig::SsoCookieVendor(_)
        ));
    }
}

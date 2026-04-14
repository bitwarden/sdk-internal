use std::sync::Arc;

use bitwarden_server_communication_config::{
    AcquiredCookie, ServerCommunicationConfig, ServerCommunicationConfigPlatformApi,
    SetCommunicationTypeRequest,
};

use crate::error::Result;

type UniffiRepository = UniffiRepositoryBridge<Arc<dyn ServerCommunicationConfigRepository>>;
type UniffiPlatformApi = UniffiPlatformApiBridge<Arc<dyn ServerCommunicationConfigPlatformApi>>;

/// UniFFI wrapper for ServerCommunicationConfigClient
#[derive(uniffi::Object)]
pub struct ServerCommunicationConfigClient {
    client: bitwarden_server_communication_config::ServerCommunicationConfigClient<
        UniffiRepository,
        UniffiPlatformApi,
    >,
}

impl ServerCommunicationConfigClient {
    /// Creates a new server communication configuration client
    pub fn new(
        repository: Arc<dyn ServerCommunicationConfigRepository>,
        platform_api: Arc<dyn ServerCommunicationConfigPlatformApi>,
    ) -> Arc<Self> {
        Arc::new(Self {
            client: bitwarden_server_communication_config::ServerCommunicationConfigClient::new(
                UniffiRepositoryBridge(repository),
                UniffiPlatformApiBridge(platform_api),
            ),
        })
    }
}

#[uniffi::export]
impl ServerCommunicationConfigClient {
    /// Retrieves the server communication configuration for a domain
    pub async fn get_config(&self, domain: String) -> Result<ServerCommunicationConfig> {
        self.client.get_config(domain).await
    }

    /// Determines if cookie bootstrapping is needed for this domain
    pub async fn needs_bootstrap(&self, domain: String) -> bool {
        self.client.needs_bootstrap(domain).await
    }

    /// Returns all cookies that should be included in requests to this server
    pub async fn cookies(&self, domain: String) -> Vec<AcquiredCookie> {
        self.client
            .cookies(domain)
            .await
            .into_iter()
            .map(|(name, value)| AcquiredCookie { name, value })
            .collect()
    }

    pub async fn get_cookies(&self, domain: String) -> Result<Vec<AcquiredCookie>> {
        let cookies = self.client.get_cookies(domain).await?;
        Ok(cookies)
    }

    /// Sets the server communication configuration for a domain
    ///
    /// This method saves the provided communication configuration to the repository.
    /// Typically called when receiving the `/api/config` response from the server.
    /// Previously acquired cookies are preserved automatically.
    #[deprecated(
        note = "Use set_communication_type_v2() instead, which extracts the domain from the config"
    )]
    pub async fn set_communication_type(
        &self,
        domain: String,
        request: SetCommunicationTypeRequest,
    ) -> Result<()> {
        #[allow(deprecated)]
        self.client.set_communication_type(domain, request).await?;
        Ok(())
    }

    /// Sets the server communication configuration using the domain from the config
    ///
    /// Extracts the `cookie_domain` from the `SsoCookieVendor` config and uses it as the
    /// storage key. If the config is `Direct` or `cookie_domain` is not set, the call
    /// is silently ignored.
    pub async fn set_communication_type_v2(
        &self,
        request: SetCommunicationTypeRequest,
    ) -> Result<()> {
        self.client.set_communication_type_v2(request).await?;
        Ok(())
    }

    /// Acquires a cookie from the platform and saves it to the repository
    pub async fn acquire_cookie(&self, domain: String) -> Result<()> {
        self.client.acquire_cookie(&domain).await?;
        Ok(())
    }
}

/// UniFFI repository trait for server communication configuration
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait ServerCommunicationConfigRepository: Send + Sync {
    /// Get configuration for a domain
    async fn get(&self, domain: String) -> Result<Option<ServerCommunicationConfig>>;

    /// Save configuration for a domain
    async fn save(&self, domain: String, config: ServerCommunicationConfig) -> Result<()>;
}

/// Bridge from UniFFI trait to internal repository trait
pub struct UniffiRepositoryBridge<T>(pub T);

impl<T: ?Sized> UniffiRepositoryBridge<Arc<T>> {
    #[allow(dead_code)]
    pub fn new(repo: Arc<T>) -> Arc<Self> {
        Arc::new(UniffiRepositoryBridge(repo))
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for UniffiRepositoryBridge<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<'a> bitwarden_server_communication_config::ServerCommunicationConfigRepository
    for UniffiRepositoryBridge<Arc<dyn ServerCommunicationConfigRepository + 'a>>
{
    type GetError = crate::error::Error;
    type SaveError = crate::error::Error;

    async fn get(
        &self,
        domain: String,
    ) -> std::result::Result<Option<ServerCommunicationConfig>, Self::GetError> {
        self.0.get(domain).await
    }

    async fn save(
        &self,
        domain: String,
        config: ServerCommunicationConfig,
    ) -> std::result::Result<(), Self::SaveError> {
        self.0.save(domain, config).await
    }
}

/// Bridge for platform API trait
pub struct UniffiPlatformApiBridge<T>(pub T);

impl<T: std::fmt::Debug> std::fmt::Debug for UniffiPlatformApiBridge<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[async_trait::async_trait]
impl<'a> ServerCommunicationConfigPlatformApi
    for UniffiPlatformApiBridge<Arc<dyn ServerCommunicationConfigPlatformApi + 'a>>
{
    async fn acquire_cookies(&self, vault_url: String) -> Option<Vec<AcquiredCookie>> {
        self.0.acquire_cookies(vault_url).await
    }
}

use std::sync::Arc;

use bitwarden_server_communication_config::{
    AcquiredCookie, ServerCommunicationConfig, ServerCommunicationConfigClient,
    ServerCommunicationConfigPlatformApi, ServerCommunicationConfigRepository,
};

use crate::error::Result;

type UniffiRepository = UniffiRepositoryBridge<Arc<dyn ServerCommunicationConfigRepositoryTrait>>;
type UniffiPlatformApi = UniffiPlatformApiBridge<Arc<dyn ServerCommunicationConfigPlatformApi>>;

/// UniFFI wrapper for ServerCommunicationConfigClient
#[derive(uniffi::Object)]
pub struct UniffiServerCommunicationConfigClient {
    client: ServerCommunicationConfigClient<UniffiRepository, UniffiPlatformApi>,
}

impl UniffiServerCommunicationConfigClient {
    /// Creates a new server communication configuration client
    pub fn new(
        repository: Arc<dyn ServerCommunicationConfigRepositoryTrait>,
        platform_api: Arc<dyn ServerCommunicationConfigPlatformApi>,
    ) -> Arc<Self> {
        Arc::new(Self {
            client: ServerCommunicationConfigClient::new(
                UniffiRepositoryBridge(repository),
                UniffiPlatformApiBridge(platform_api),
            ),
        })
    }
}

#[uniffi::export]
impl UniffiServerCommunicationConfigClient {
    /// Retrieves the server communication configuration for a hostname
    pub async fn get_config(&self, hostname: String) -> Result<ServerCommunicationConfig> {
        self.client.get_config(hostname).await
    }

    /// Determines if cookie bootstrapping is needed for this hostname
    pub async fn needs_bootstrap(&self, hostname: String) -> bool {
        self.client.needs_bootstrap(hostname).await
    }

    /// Returns all cookies that should be included in requests to this server
    pub async fn cookies(&self, hostname: String) -> Vec<AcquiredCookie> {
        self.client
            .cookies(hostname)
            .await
            .into_iter()
            .map(|(name, value)| AcquiredCookie { name, value })
            .collect()
    }

    /// Acquires a cookie from the platform and saves it to the repository
    pub async fn acquire_cookie(&self, hostname: String) -> Result<()> {
        self.client.acquire_cookie(&hostname).await?;
        Ok(())
    }
}

/// UniFFI repository trait for server communication configuration
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait ServerCommunicationConfigRepositoryTrait: Send + Sync {
    /// Get configuration for a hostname
    async fn get(&self, hostname: String) -> Result<Option<ServerCommunicationConfig>>;

    /// Save configuration for a hostname
    async fn save(&self, hostname: String, config: ServerCommunicationConfig) -> Result<()>;
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

impl<'a> ServerCommunicationConfigRepository
    for UniffiRepositoryBridge<Arc<dyn ServerCommunicationConfigRepositoryTrait + 'a>>
{
    type GetError = crate::error::Error;
    type SaveError = crate::error::Error;

    async fn get(
        &self,
        hostname: String,
    ) -> std::result::Result<Option<ServerCommunicationConfig>, Self::GetError> {
        self.0.get(hostname).await
    }

    async fn save(
        &self,
        hostname: String,
        config: ServerCommunicationConfig,
    ) -> std::result::Result<(), Self::SaveError> {
        self.0.save(hostname, config).await
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
    async fn acquire_cookies(&self, hostname: String) -> Option<Vec<AcquiredCookie>> {
        self.0.acquire_cookies(hostname).await
    }
}

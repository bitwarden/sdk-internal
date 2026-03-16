#![doc = include_str!("../README.md")]

#[cfg(feature = "bitwarden-license")]
mod commercial;

use std::sync::Arc;

use bitwarden_auth::{AuthClientExt as _, token_management::PasswordManagerTokenHandler};
use bitwarden_core::auth::{ClientManagedTokenHandler, ClientManagedTokens};
use bitwarden_exporters::ExporterClientExt as _;
use bitwarden_generators::GeneratorClientsExt as _;
use bitwarden_send::SendClientExt as _;
use bitwarden_server_communication_config::{
    ServerCommunicationConfigClient, ServerCommunicationConfigPlatformApi,
    ServerCommunicationConfigRepository,
};
use bitwarden_user_crypto_management::UserCryptoManagementClientExt;
use bitwarden_vault::VaultClientExt as _;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

/// Re-export subclients for easier access
pub mod clients {
    pub use bitwarden_auth::AuthClient;
    pub use bitwarden_core::key_management::CryptoClient;
    pub use bitwarden_exporters::ExporterClient;
    pub use bitwarden_generators::GeneratorClient;
    pub use bitwarden_send::SendClient;
    pub use bitwarden_vault::VaultClient;
}
#[cfg(feature = "bitwarden-license")]
pub use commercial::CommercialPasswordManagerClient;

pub mod migrations;

/// The main entry point for the Bitwarden Password Manager SDK
pub struct PasswordManagerClient(pub bitwarden_core::Client);

impl PasswordManagerClient {
    /// Initialize a new instance of the SDK client
    pub fn new(settings: Option<bitwarden_core::ClientSettings>) -> Self {
        let token_handler = Arc::new(PasswordManagerTokenHandler::default());
        Self(bitwarden_core::Client::new_with_token_handler(
            settings,
            token_handler,
        ))
    }

    /// Initialize a new instance of the SDK client with client-managed tokens
    pub fn new_with_client_tokens(
        settings: Option<bitwarden_core::ClientSettings>,
        tokens: Arc<dyn ClientManagedTokens>,
    ) -> Self {
        Self(bitwarden_core::Client::new_with_token_handler(
            settings,
            ClientManagedTokenHandler::new(tokens),
        ))
    }

    /// Initialize a new instance of the SDK client with SSO cookie middleware.
    ///
    /// Use this constructor when the deployment requires session-affinity cookies
    /// (e.g., self-hosted behind AWS ALB). The provided
    /// `communication_config_client` will supply cookies on each API request.
    pub fn new_with_communication_config<R, P>(
        settings: Option<bitwarden_core::ClientSettings>,
        communication_config_client: ServerCommunicationConfigClient<R, P>,
    ) -> Self
    where
        R: ServerCommunicationConfigRepository + Send + Sync + 'static,
        P: ServerCommunicationConfigPlatformApi + Send + Sync + 'static,
    {
        let token_handler = Arc::new(PasswordManagerTokenHandler::default());
        let cookie_middleware = communication_config_client.create_middleware_arc();
        Self(
            bitwarden_core::Client::new_with_token_handler_and_cookie_middleware(
                settings,
                token_handler,
                cookie_middleware,
            ),
        )
    }

    /// Platform operations
    pub fn platform(&self) -> bitwarden_core::platform::PlatformClient {
        self.0.platform()
    }

    /// Auth operations
    pub fn auth(&self) -> bitwarden_auth::AuthClient {
        self.0.auth_new()
    }

    /// Bitwarden licensed operations
    #[cfg(feature = "bitwarden-license")]
    pub fn commercial(&self) -> CommercialPasswordManagerClient {
        CommercialPasswordManagerClient::new(self.0.clone())
    }

    /// Crypto operations
    pub fn crypto(&self) -> bitwarden_core::key_management::CryptoClient {
        self.0.crypto()
    }

    /// Operations that manage the cryptographic machinery of a user account, including key-rotation
    pub fn user_crypto_management(
        &self,
    ) -> bitwarden_user_crypto_management::UserCryptoManagementClient {
        self.0.user_crypto_management()
    }

    /// Vault item operations
    pub fn vault(&self) -> bitwarden_vault::VaultClient {
        self.0.vault()
    }

    /// Exporter operations
    pub fn exporters(&self) -> bitwarden_exporters::ExporterClient {
        self.0.exporters()
    }

    /// Generator operations
    pub fn generator(&self) -> bitwarden_generators::GeneratorClient {
        self.0.generator()
    }

    /// Send operations
    pub fn sends(&self) -> bitwarden_send::SendClient {
        self.0.sends()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use bitwarden_server_communication_config::{
        AcquiredCookie, ServerCommunicationConfig, ServerCommunicationConfigRepository,
    };
    use tokio::sync::RwLock;

    use super::*;

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

    #[derive(Clone)]
    struct MockPlatformApi;

    #[async_trait::async_trait]
    impl bitwarden_server_communication_config::ServerCommunicationConfigPlatformApi
        for MockPlatformApi
    {
        async fn acquire_cookies(&self, _hostname: String) -> Option<Vec<AcquiredCookie>> {
            None
        }
    }

    #[tokio::test]
    async fn new_with_communication_config_constructs_successfully() {
        let repo = MockRepository::default();
        let platform_api = MockPlatformApi;
        let communication_config_client = ServerCommunicationConfigClient::new(repo, platform_api);

        let client =
            PasswordManagerClient::new_with_communication_config(None, communication_config_client);

        // Verify the client is constructed (has internal state accessible)
        let _ = client.crypto();
    }
}

#![doc = include_str!("../README.md")]

#[cfg(feature = "bitwarden-license")]
mod commercial;

use std::sync::Arc;

use bitwarden_auth::{AuthClientExt as _, token_management::PasswordManagerTokenHandler};
use bitwarden_core::{
    FromClient,
    auth::{ClientManagedTokenHandler, ClientManagedTokens},
};
use bitwarden_exporters::ExporterClientExt as _;
use bitwarden_generators::GeneratorClientsExt as _;
use bitwarden_send::SendClientExt as _;
use bitwarden_sync::SyncClientExt as _;
use bitwarden_user_crypto_management::UserCryptoManagementClientExt;
use bitwarden_vault::{FolderSyncHandler, VaultClientExt as _};

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

/// Re-export subclients for easier access
pub mod clients {
    pub use bitwarden_auth::AuthClient;
    pub use bitwarden_core::key_management::CryptoClient;
    pub use bitwarden_exporters::ExporterClient;
    pub use bitwarden_generators::GeneratorClient;
    pub use bitwarden_send::SendClient;
    pub use bitwarden_sync::SyncClient;
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

    /// Initialize a new instance of the SDK client with SDK managed state and sync handlers
    /// registered
    ///
    /// This will eventually replace `new` when the SDK fully owns sync on all clients.
    pub fn new_with_sync(settings: Option<bitwarden_core::ClientSettings>) -> Result<Self, String> {
        let client = Self::new(settings);

        client
            .sync()
            .register_sync_handler(Arc::new(FolderSyncHandler::from_client(&client.0)?));

        // TODO: Add more sync handlers here!

        Ok(client)
    }

    /// Initialize a new instance of the SDK client with SSO cookie injection middleware.
    ///
    /// Wires a ServerCommunicationConfigClient into the API HTTP client middleware
    /// layer. The identity HTTP client is not affected.
    pub fn new_with_server_communication_config<R, P>(
        settings: Option<bitwarden_core::ClientSettings>,
        server_communication_config_client: bitwarden_server_communication_config::ServerCommunicationConfigClient<R, P>,
    ) -> Self
    where
        R: bitwarden_server_communication_config::ServerCommunicationConfigRepository
            + Clone
            + Send
            + Sync
            + 'static,
        P: bitwarden_server_communication_config::ServerCommunicationConfigPlatformApi
            + Clone
            + Send
            + Sync
            + 'static,
    {
        let token_handler = Arc::new(PasswordManagerTokenHandler::default());
        let (middleware, lock) = bitwarden_server_communication_config::create_middleware(
            server_communication_config_client,
        );
        Self(bitwarden_core::Client::new_with_middlewares(
            settings,
            token_handler,
            vec![middleware],
            vec![lock],
        ))
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

    /// Sync operations
    pub fn sync(&self) -> bitwarden_sync::SyncClient {
        self.0.sync()
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use bitwarden_server_communication_config::{
        AcquiredCookie, ServerCommunicationConfig, ServerCommunicationConfigClient,
        ServerCommunicationConfigPlatformApi, ServerCommunicationConfigRepository,
    };
    use tokio::sync::RwLock;

    #[derive(Default, Clone)]
    struct MockRepo {
        storage: Arc<RwLock<HashMap<String, ServerCommunicationConfig>>>,
    }

    impl ServerCommunicationConfigRepository for MockRepo {
        type GetError = ();
        type SaveError = ();

        async fn get(
            &self,
            hostname: String,
        ) -> Result<Option<ServerCommunicationConfig>, ()> {
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
    struct MockApi;

    #[async_trait::async_trait]
    impl ServerCommunicationConfigPlatformApi for MockApi {
        async fn acquire_cookies(&self, _vault_url: String) -> Option<Vec<AcquiredCookie>> {
            None
        }
    }

    #[test]
    fn new_with_server_communication_config_compiles() {
        let cookie_client = ServerCommunicationConfigClient::new(MockRepo::default(), MockApi);
        let _client = super::PasswordManagerClient::new_with_server_communication_config(
            None,
            cookie_client,
        );
    }

    #[test]
    fn existing_constructors_unchanged() {
        // new() uses the standard token handler and constructs without runtime setup
        let _c1 = super::PasswordManagerClient::new(None);
        // new_with_sync() requires state registry initialization at runtime;
        // verify it compiles by referencing its function pointer type only
        let _: fn(
            Option<bitwarden_core::ClientSettings>,
        ) -> Result<super::PasswordManagerClient, String> =
            super::PasswordManagerClient::new_with_sync;
    }
}

#![doc = include_str!("../README.md")]

#[cfg(feature = "bitwarden-license")]
mod commercial;

use std::sync::Arc;

use bitwarden_auth::AuthClientExt as _;
use bitwarden_core::{
    FromClient,
    auth::{ClientManagedTokenHandler, ClientManagedTokens},
    client::persisted_state::SESSION_PROTECTED_USER_KEY,
};
use bitwarden_exporters::ExporterClientExt as _;
use bitwarden_generators::GeneratorClientsExt as _;
use bitwarden_policies::PoliciesClientExt as _;
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
    pub use bitwarden_policies::PolicyClient;
    pub use bitwarden_send::SendClient;
    pub use bitwarden_sync::SyncClient;
    pub use bitwarden_vault::VaultClient;
}
#[cfg(feature = "bitwarden-license")]
pub use commercial::CommercialPasswordManagerClient;

mod builder;
pub mod migrations;
pub use bitwarden_core::{RehydrationError, SaveStateData};
pub use builder::PasswordManagerClientBuilder;

/// The main entry point for the Bitwarden Password Manager SDK
pub struct PasswordManagerClient(pub bitwarden_core::Client);

impl PasswordManagerClient {
    /// Initialize a new instance of the SDK client
    pub fn new(settings: Option<bitwarden_core::ClientSettings>) -> Self {
        let mut builder = PasswordManagerClientBuilder::new();
        if let Some(s) = settings {
            builder = builder.with_settings(s);
        }
        builder.build()
    }

    /// Returns a [`PasswordManagerClientBuilder`] for constructing a new [`PasswordManagerClient`].
    pub fn builder() -> PasswordManagerClientBuilder {
        PasswordManagerClientBuilder::new()
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
    pub fn new_with_sync(settings: Option<bitwarden_core::ClientSettings>) -> Self {
        let client = Self::new(settings);

        client
            .sync()
            .register_sync_handler(Arc::new(FolderSyncHandler::from_client(&client.0)));

        // TODO: Add more sync handlers here!

        client
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

    /// Feature flag operations
    pub fn flags(&self) -> bitwarden_core::FlagsClient {
        self.0.flags()
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

    /// Policy operations
    pub fn policies(&self) -> bitwarden_policies::PolicyClient {
        self.0.policies()
    }

    /// Sync operations
    pub fn sync(&self) -> bitwarden_sync::SyncClient {
        self.0.sync()
    }

    /// Returns true when the user's symmetric key is loaded into the key store.
    pub fn is_unlocked(&self) -> bool {
        use bitwarden_core::key_management::SymmetricKeySlotId;
        self.0
            .internal
            .get_key_store()
            .context()
            .has_symmetric_key(SymmetricKeySlotId::User)
    }

    /// Invalidate the persisted session key, locking the vault for future invocations.
    ///
    /// Removes [`SESSION_PROTECTED_USER_KEY`] from the database. Distinct from
    /// `lock()` on long-lived clients (mobile, desktop), which clears keys from memory: the
    /// CLI process exits between invocations, so locking must delete the persisted session
    /// key rather than mutate in-memory state.
    pub async fn invalidate_session_key(&self) -> Result<(), bitwarden_state::SettingsError> {
        self.0
            .platform()
            .state()
            .setting(SESSION_PROTECTED_USER_KEY)?
            .delete()
            .await
    }

    /// Write rehydration state to a StateRegistry.
    ///
    /// Delegates to [`Client::save_to_state`](bitwarden_core::Client::save_to_state).
    pub async fn save_to_state(
        data: SaveStateData,
        reg: &bitwarden_state::registry::StateRegistry,
    ) -> Result<(), RehydrationError> {
        bitwarden_core::Client::save_to_state(data, reg).await
    }

    /// Reconstruct a locked PasswordManagerClient from a populated StateRegistry.
    ///
    /// Delegates to [`Client::load_from_state`](bitwarden_core::Client::load_from_state).
    pub async fn load_from_state(
        token_handler: std::sync::Arc<dyn bitwarden_core::auth::auth_tokens::TokenHandler>,
        registry: bitwarden_state::registry::StateRegistry,
    ) -> Result<Self, RehydrationError> {
        let client = bitwarden_core::Client::load_from_state(token_handler, registry).await?;
        Ok(PasswordManagerClient(client))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn new_with_server_communication_config_constructs() {
        struct MockCookieProvider;

        #[async_trait::async_trait]
        impl bitwarden_server_communication_config::CookieProvider for MockCookieProvider {
            async fn cookies(&self, _hostname: &str) -> Vec<(String, String)> {
                vec![]
            }

            async fn acquire_cookie(
                &self,
                _hostname: &str,
            ) -> Result<(), bitwarden_server_communication_config::AcquireCookieError> {
                Ok(())
            }

            async fn needs_bootstrap(&self, _hostname: &str) -> bool {
                false
            }
        }

        let _client = PasswordManagerClient::builder()
            .with_server_communication_config(Arc::new(MockCookieProvider))
            .build();
    }
}

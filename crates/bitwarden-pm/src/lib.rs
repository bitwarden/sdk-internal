#![doc = include_str!("../README.md")]

#[cfg(feature = "bitwarden-license")]
mod commercial;

use std::sync::Arc;

use bitwarden_auth::AuthClientExt as _;
use bitwarden_core::{
    FromClient,
    auth::{ClientManagedTokenHandler, ClientManagedTokens},
    client::{
        client_settings::get_host_platform_info,
        persisted_state::{BASE_URLS, BaseUrls, SESSION_PROTECTED_USER_KEY},
    },
};
use bitwarden_crypto::{SymmetricCryptoKey, SymmetricKeyAlgorithm};
use bitwarden_error::bitwarden_error;
use bitwarden_exporters::ExporterClientExt as _;
use bitwarden_generators::GeneratorClientsExt as _;
use bitwarden_policies::PoliciesClientExt as _;
use bitwarden_send::SendClientExt as _;
use bitwarden_state::registry::StateRegistry;
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
pub use builder::PasswordManagerClientBuilder;

/// The main entry point for the Bitwarden Password Manager SDK
pub struct PasswordManagerClient(pub bitwarden_core::Client);

/// Errors that can occur during client rehydration operations.
#[bitwarden_error(flat)]
#[derive(Debug, thiserror::Error)]
pub enum RehydrationError {
    /// The session key does not decrypt the wrapped user key (wrong key presented
    /// to [`PasswordManagerClient::unlock_from_state`]).
    #[error("Session key does not decrypt stored user key")]
    NotAuthenticated,
    /// A state read/write operation failed.
    #[error(transparent)]
    State(#[from] bitwarden_state::SettingsError),
    /// A key wrapping or unwrapping operation failed.
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
    /// A required state setting is absent (e.g. ACCOUNT_CRYPTO_STATE not found).
    #[error("Required state setting is missing")]
    MissingState,
}

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

    /// Generates a fresh session key and persists the user key wrapped by it.
    ///
    /// The session key is an ephemeral XChaCha20-Poly1305 key used to protect
    /// the user key between CLI invocations. The wrapped user key is stored as
    /// [`SESSION_PROTECTED_USER_KEY`] in the state registry.
    ///
    /// Returns the raw session key bytes. The caller is responsible for storing
    /// these bytes securely (e.g., in the OS keychain or a secure enclave).
    ///
    /// # Errors
    ///
    /// Returns an error if the user key is not loaded or if state persistence fails.
    pub async fn generate_session_key(&self) -> Result<Vec<u8>, RehydrationError> {
        use bitwarden_core::key_management::SymmetricKeySlotId;

        let (session_key_id, wrapped_user_key) = {
            let mut ctx = self.0.internal.get_key_store().context_mut();
            let session_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
            let wrapped_user_key = ctx
                .wrap_symmetric_key(session_key_id, SymmetricKeySlotId::User)
                .map_err(RehydrationError::Crypto)?;
            (session_key_id, wrapped_user_key)
        };

        self.0
            .platform()
            .state()
            .setting(SESSION_PROTECTED_USER_KEY)
            .map_err(RehydrationError::State)?
            .update(wrapped_user_key)
            .await
            .map_err(RehydrationError::State)?;

        let session_key_bytes = {
            let ctx = self.0.internal.get_key_store().context_mut();
            #[allow(deprecated)]
            ctx.dangerous_get_symmetric_key(session_key_id)
                .map_err(RehydrationError::Crypto)?
                .to_encoded()
                .to_vec()
        };

        Ok(session_key_bytes)
    }

    /// Persists the client's base URLs into the state registry.
    ///
    /// Must be called after login and before the process exits, so that
    /// [`PasswordManagerClient::load_from_state`] can reconstruct [`ClientSettings`]
    /// on the next invocation.
    ///
    /// # Errors
    ///
    /// Returns an error if the registry operation fails.
    pub async fn save_to_state(&self) -> Result<(), RehydrationError> {
        let api_configs = self.0.internal.get_api_configurations();
        let base_urls = BaseUrls {
            identity_url: api_configs.identity_config.base_path.clone(),
            api_url: api_configs.api_config.base_path.clone(),
        };

        self.0
            .platform()
            .state()
            .setting(BASE_URLS)?
            .update(base_urls)
            .await?;
        Ok(())
    }

    /// Reconstructs a [`PasswordManagerClient`] from persisted state.
    ///
    /// Reads [`USER_ID`] and [`BASE_URLS`] from the registry, constructs
    /// [`ClientSettings`] using the globally-initialized [`HostPlatformInfo`]
    /// (set via [`bitwarden_core::client::client_settings::init_host_platform_info`]),
    /// and returns a fully wired client backed by the provided registry.
    ///
    /// # Panics
    ///
    /// Panics if [`init_host_platform_info`] has not been called before this function.
    ///
    /// # Errors
    ///
    /// Returns an error if [`USER_ID`] or [`BASE_URLS`] are missing from the registry,
    /// or if registry operations fail.
    pub async fn load_from_state(registry: StateRegistry) -> Result<Self, RehydrationError> {
        use bitwarden_core::{
            UserId,
            client::persisted_state::{BASE_URLS, USER_ID},
        };

        // Read USER_ID directly as UserId (Deviation 2: stored as UserId, not String)
        let user_id: UserId = registry
            .setting(USER_ID)
            .map_err(|e| RehydrationError::State(e.into()))?
            .get()
            .await
            .map_err(RehydrationError::State)?
            .ok_or(RehydrationError::MissingState)?;

        // Read BASE_URLS for constructing ClientSettings
        let base_urls = registry
            .setting(BASE_URLS)
            .map_err(|e| RehydrationError::State(e.into()))?
            .get()
            .await
            .map_err(RehydrationError::State)?
            .ok_or(RehydrationError::MissingState)?;

        // Build ClientSettings from HostPlatformInfo (Deviation 5: no AppSettings type)
        // Panics if init_host_platform_info was not called — documented above
        let platform = get_host_platform_info();
        let settings = bitwarden_core::ClientSettings {
            identity_url: base_urls.identity_url,
            api_url: base_urls.api_url,
            user_agent: platform.user_agent.clone(),
            device_type: platform.device_type,
            device_identifier: platform.device_identifier.clone(),
            bitwarden_client_version: platform.bitwarden_client_version.clone(),
            bitwarden_package_type: platform.bitwarden_package_type.clone(),
        };

        // Construct client with the existing registry (Deviation 4: use
        // PasswordManagerClientBuilder)
        let client = PasswordManagerClientBuilder::new()
            .with_settings(settings)
            .with_state(registry)
            .build();

        // Initialize the user ID on the newly constructed client
        client
            .0
            .internal
            .init_user_id(user_id)
            .await
            .map_err(|_| RehydrationError::MissingState)?;

        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn init_platform_info_for_tests() {
        bitwarden_core::init_host_platform_info(bitwarden_core::HostPlatformInfo {
            user_agent: "test-agent".to_string(),
            device_type: bitwarden_core::DeviceType::SDK,
            device_identifier: None,
            bitwarden_client_version: None,
            bitwarden_package_type: None,
        });
    }


    async fn load_from_state_round_trips_user_id() {
        use bitwarden_core::{UserId, client::persisted_state::USER_ID};

        init_platform_info_for_tests();

        let registry = StateRegistry::new_with_memory_db();
        let user_id = UserId::new_v4();

        registry
            .setting(USER_ID)
            .expect("USER_ID key should be registered")
            .update(user_id)
            .await
            .expect("seeding USER_ID should succeed");

        registry
            .setting(BASE_URLS)
            .expect("BASE_URLS key should be registered")
            .update(BaseUrls {
                identity_url: "https://identity.bitwarden.com".to_string(),
                api_url: "https://api.bitwarden.com".to_string(),
            })
            .await
            .expect("seeding BASE_URLS should succeed");

        let client = PasswordManagerClient::load_from_state(registry)
            .await
            .expect("load_from_state should succeed");

        assert_eq!(
            client.0.internal.get_user_id(),
            Some(user_id),
            "loaded client should have seeded user_id"
        );
    }

    #[tokio::test]
    async fn load_from_state_fails_without_user_id() {
        init_platform_info_for_tests();

        let registry = StateRegistry::new_with_memory_db();

        registry
            .setting(BASE_URLS)
            .expect("BASE_URLS key should be registered")
            .update(BaseUrls {
                identity_url: "https://identity.bitwarden.com".to_string(),
                api_url: "https://api.bitwarden.com".to_string(),
            })
            .await
            .expect("seeding BASE_URLS should succeed");

        let result = PasswordManagerClient::load_from_state(registry).await;
        assert!(
            matches!(result, Err(RehydrationError::MissingState)),
            "expected MissingState"
        );
    }

    #[tokio::test]
    async fn load_from_state_fails_without_base_urls() {
        use bitwarden_core::{UserId, client::persisted_state::USER_ID};

        init_platform_info_for_tests();

        let registry = StateRegistry::new_with_memory_db();
        let user_id = UserId::new_v4();

        registry
            .setting(USER_ID)
            .expect("USER_ID key should be registered")
            .update(user_id)
            .await
            .expect("seeding USER_ID should succeed");

        let result = PasswordManagerClient::load_from_state(registry).await;
        assert!(
            matches!(result, Err(RehydrationError::MissingState)),
            "expected MissingState"
        );
    }


    #[tokio::test]
    async fn save_to_state_persists_base_urls() {
        use bitwarden_core::{ClientSettings, client::persisted_state::BASE_URLS};

        let settings = ClientSettings {
            identity_url: "https://test-identity.example.com".to_string(),
            api_url: "https://test-api.example.com".to_string(),
            ..ClientSettings::default()
        };
        let client = PasswordManagerClient::new(Some(settings));

        client
            .save_to_state()
            .await
            .expect("save_to_state should succeed");

        let stored = client
            .platform()
            .state()
            .setting(BASE_URLS)
            .expect("BASE_URLS key should be registered")
            .get()
            .await
            .expect("get should succeed")
            .expect("BASE_URLS should be set after save_to_state");

        assert_eq!(stored.identity_url, "https://test-identity.example.com");
        assert_eq!(stored.api_url, "https://test-api.example.com");
    }

    #[tokio::test]
    async fn generate_session_key_fails_when_not_unlocked() {
        let client = PasswordManagerClient::new(None);
        let result = client.generate_session_key().await;
        assert!(
            result.is_err(),
            "expected error when user key is not loaded"
        );
    }

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

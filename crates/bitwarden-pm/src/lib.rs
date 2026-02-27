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
    ServerCommunicationConfigClient, ServerCommunicationConfigMiddleware,
    ServerCommunicationConfigPlatformApi, ServerCommunicationConfigRepository,
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

    /// Creates a new PasswordManagerClient with ServerCommunicationConfig cookie support.
    ///
    /// This constructor variant enables SSO cookie attachment for self-hosted deployments
    /// behind load balancers requiring session affinity (e.g., AWS Elastic Load Balancer).
    /// The repository and platform API implementations are injected by the platform layer.
    ///
    /// # Type Parameters
    ///
    /// * `R` - ServerCommunicationConfigRepository implementation for cookie storage
    ///   (e.g., StateProviderRepository for TypeScript State Provider integration)
    /// * `P` - ServerCommunicationConfigPlatformApi implementation for cookie acquisition
    ///   (e.g., NativePlatformApi for WebView-based cookie flows)
    ///
    /// # Arguments
    ///
    /// * `settings` - Optional client settings (API URLs, device type, user agent)
    /// * `server_comm_repo` - Repository implementation for storing/retrieving cookie configuration
    /// * `server_comm_platform_api` - Platform API implementation for acquiring cookies via IDP
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use bitwarden_pm::PasswordManagerClient;
    /// use my_platform::{StateProviderRepository, NativePlatformApi};
    ///
    /// let repo = StateProviderRepository::new(state_provider);
    /// let platform_api = NativePlatformApi::new();
    /// let client = PasswordManagerClient::new_with_server_comm_config(
    ///     Some(settings),
    ///     repo,
    ///     platform_api,
    /// );
    /// ```
    ///
    /// # Notes
    ///
    /// - Cookie middleware is registered BEFORE authentication middleware per ADR-056
    /// - For standard deployments without SSO cookies, use `PasswordManagerClient::new()`
    /// - This constructor is additive; existing `new()` behavior is unchanged
    pub fn new_with_server_comm_config<R, P>(
        settings: Option<bitwarden_core::ClientSettings>,
        server_comm_repo: R,
        server_comm_platform_api: P,
    ) -> Self
    where
        R: ServerCommunicationConfigRepository + 'static,
        P: ServerCommunicationConfigPlatformApi + 'static,
    {
        // Instantiate ServerCommunicationConfigClient with injected dependencies
        let server_comm_client = Arc::new(ServerCommunicationConfigClient::new(
            server_comm_repo,
            server_comm_platform_api,
        ));

        // Create cookie middleware wrapping the client
        let cookie_middleware: Arc<dyn reqwest_middleware::Middleware> =
            Arc::new(ServerCommunicationConfigMiddleware::new(server_comm_client));

        // Use PasswordManagerTokenHandler (same as PasswordManagerClient::new())
        let token_handler = Arc::new(PasswordManagerTokenHandler::default());

        // Delegate to Client::new_with_middleware() with cookie middleware
        let client = bitwarden_core::Client::new_with_middleware(
            settings,
            token_handler,
            Some(cookie_middleware),
        );

        PasswordManagerClient(client)
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

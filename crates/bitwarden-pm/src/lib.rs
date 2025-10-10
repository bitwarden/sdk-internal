#![doc = include_str!("../README.md")]

#[cfg(feature = "bitwarden-license")]
mod commercial;

use std::sync::Arc;

use bitwarden_auth::AuthClientExt as _;
use bitwarden_core::client::internal::ClientManagedTokens;
use bitwarden_exporters::ExporterClientExt as _;
use bitwarden_generators::GeneratorClientsExt as _;
use bitwarden_send::SendClientExt as _;
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

/// The main entry point for the Bitwarden Password Manager SDK
pub struct PasswordManagerClient(pub bitwarden_core::Client);

impl PasswordManagerClient {
    /// Initialize a new instance of the SDK client
    pub fn new(settings: Option<bitwarden_core::ClientSettings>) -> Self {
        Self(bitwarden_core::Client::new(settings))
    }

    /// Initialize a new instance of the SDK client with client-managed tokens
    pub fn new_with_client_tokens(
        settings: Option<bitwarden_core::ClientSettings>,
        tokens: Arc<dyn ClientManagedTokens>,
    ) -> Self {
        Self(bitwarden_core::Client::new_with_client_tokens(
            settings, tokens,
        ))
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

#![doc = include_str!("../README.md")]

uniffi::setup_scaffolding!();

use std::sync::Arc;

use auth::AuthClient;
use bitwarden_core::{ClientSettings, client::internal::ClientManagedTokens};

#[allow(missing_docs)]
pub mod auth;
#[allow(missing_docs)]
pub mod crypto;
mod error;
#[allow(missing_docs)]
pub mod platform;
#[allow(missing_docs)]
pub mod tool;
mod uniffi_support;
#[allow(missing_docs)]
pub mod vault;

#[cfg(target_os = "android")]
mod android_support;

use crypto::CryptoClient;
use error::{Error, Result};
use platform::PlatformClient;
use tool::{ExporterClient, GeneratorClients, SendClient, SshClient};
use vault::VaultClient;

#[allow(missing_docs)]
#[derive(uniffi::Object)]
pub struct Client(pub(crate) bitwarden_pm::PasswordManagerClient);

#[uniffi::export(async_runtime = "tokio")]
impl Client {
    /// Initialize a new instance of the SDK client
    #[uniffi::constructor]
    pub fn new(
        token_provider: Arc<dyn ClientManagedTokens>,
        settings: Option<ClientSettings>,
    ) -> Self {
        init_logger();
        setup_error_converter();

        #[cfg(target_os = "android")]
        android_support::init();

        Self(bitwarden_pm::PasswordManagerClient::new_with_client_tokens(
            settings,
            token_provider,
        ))
    }

    /// Crypto operations
    pub fn crypto(&self) -> CryptoClient {
        CryptoClient(self.0.crypto())
    }

    /// Vault item operations
    pub fn vault(&self) -> VaultClient {
        VaultClient(self.0.vault())
    }

    #[allow(missing_docs)]
    pub fn platform(&self) -> PlatformClient {
        PlatformClient(self.0.0.clone())
    }

    /// Generator operations
    pub fn generators(&self) -> GeneratorClients {
        GeneratorClients(self.0.generator())
    }

    /// Exporters
    pub fn exporters(&self) -> ExporterClient {
        ExporterClient(self.0.exporters())
    }

    /// Sends operations
    pub fn sends(&self) -> SendClient {
        SendClient(self.0.sends())
    }

    /// SSH operations
    pub fn ssh(&self) -> SshClient {
        SshClient()
    }

    /// Auth operations
    pub fn auth(&self) -> AuthClient {
        AuthClient(self.0.0.clone())
    }

    /// Test method, echoes back the input
    pub fn echo(&self, msg: String) -> String {
        msg
    }

    /// Test method, calls http endpoint
    pub async fn http_get(&self, url: String) -> Result<String> {
        let client = self.0.0.internal.get_http_client();
        let res = client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Api(e.into()))?;

        res.text().await.map_err(|e| Error::Api(e.into()))
    }
}

fn init_logger() {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .try_init();

    #[cfg(target_os = "ios")]
    let _ = oslog::OsLogger::new("com.8bit.bitwarden")
        .level_filter(log::LevelFilter::Info)
        .init();

    #[cfg(target_os = "android")]
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("com.bitwarden.sdk")
            .with_max_level(log::LevelFilter::Info),
    );
}

/// Setup the error converter to ensure conversion errors don't cause panics
/// Check [`bitwarden_uniffi_error`] for more details
fn setup_error_converter() {
    bitwarden_uniffi_error::set_error_to_uniffi_error(|e| {
        crate::error::BitwardenError::Conversion(e.to_string()).into()
    });
}

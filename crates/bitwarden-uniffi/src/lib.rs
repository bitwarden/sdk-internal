uniffi::setup_scaffolding!();

use std::sync::Arc;

use auth::AuthClient;
use bitwarden_core::ClientSettings;

pub mod auth;
pub mod crypto;
mod error;
pub mod platform;
pub mod tool;
mod uniffi_support;
pub mod vault;

#[cfg(target_os = "android")]
mod android_support;

use crypto::CryptoClient;
use error::{Error, Result};
use platform::PlatformClient;
use tool::{ExporterClient, GeneratorClients, SendClient, SshClient};
use vault::VaultClient;

#[derive(uniffi::Object)]
pub struct Client(bitwarden_core::Client);

#[uniffi::export(async_runtime = "tokio")]
impl Client {
    /// Initialize a new instance of the SDK client
    #[uniffi::constructor]
    pub fn new(settings: Option<ClientSettings>) -> Arc<Self> {
        init_logger();

        #[cfg(target_os = "android")]
        android_support::init();

        Arc::new(Self(bitwarden_core::Client::new(settings)))
    }

    /// Crypto operations
    pub fn crypto(self: Arc<Self>) -> Arc<CryptoClient> {
        Arc::new(CryptoClient(self))
    }

    /// Vault item operations
    pub fn vault(self: Arc<Self>) -> Arc<VaultClient> {
        Arc::new(VaultClient(self))
    }

    pub fn platform(self: Arc<Self>) -> Arc<PlatformClient> {
        Arc::new(PlatformClient(self))
    }

    /// Generator operations
    pub fn generators(self: Arc<Self>) -> Arc<GeneratorClients> {
        Arc::new(GeneratorClients(self))
    }

    /// Exporters
    pub fn exporters(self: Arc<Self>) -> Arc<ExporterClient> {
        Arc::new(ExporterClient(self))
    }

    /// Sends operations
    pub fn sends(self: Arc<Self>) -> Arc<SendClient> {
        Arc::new(SendClient(self))
    }

    /// SSH operations
    pub fn ssh(self: Arc<Self>) -> Arc<SshClient> {
        Arc::new(SshClient(self))
    }

    /// Auth operations
    pub fn auth(self: Arc<Self>) -> Arc<AuthClient> {
        Arc::new(AuthClient(self))
    }

    /// Test method, echoes back the input
    pub fn echo(&self, msg: String) -> String {
        msg
    }

    /// Test method, calls http endpoint
    pub async fn http_get(&self, url: String) -> Result<String> {
        let client = self.0.internal.get_http_client();
        let res = client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Api(e.into()))?;

        Ok(res.text().await.map_err(|e| Error::Api(e.into()))?)
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
        android_logger::Config::default().with_max_level(uniffi::deps::log::LevelFilter::Info),
    );
}

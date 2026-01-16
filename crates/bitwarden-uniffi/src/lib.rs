#![doc = include_str!("../README.md")]

uniffi::setup_scaffolding!();

use std::sync::{Arc, Once};

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

static INIT: Once = Once::new();

fn init_logger() {
    use tracing_subscriber::{EnvFilter, layer::SubscriberExt as _, util::SubscriberInitExt as _};

    INIT.call_once(|| {
        // the log level prioritization is determined by:
        //    1. if RUST_LOG is detected at runtime
        //    2. if RUST_LOG is provided at compile time
        //    3. default to INFO
        let filter = EnvFilter::builder()
            .with_default_directive(
                option_env!("RUST_LOG")
                    .unwrap_or("info")
                    .parse()
                    .expect("should provide valid log level at compile time."),
            )
            .from_env_lossy();

        let fmtlayer = tracing_subscriber::fmt::layer()
            .with_ansi(true)
            .with_file(true)
            .with_line_number(true)
            .with_target(true)
            .pretty();

        #[cfg(target_os = "ios")]
        {
            const TAG: &str = "com.8bit.bitwarden";

            tracing_subscriber::registry()
                .with(fmtlayer)
                .with(filter)
                .with(tracing_oslog::OsLogger::new(TAG, "default"))
                .init();
        }

        #[cfg(target_os = "android")]
        {
            const TAG: &str = "com.bitwarden.sdk";

            tracing_subscriber::registry()
                .with(fmtlayer)
                .with(filter)
                .with(
                    tracing_android::layer(TAG)
                        .expect("initialization of android logcat tracing layer"),
                )
                .init();
        }

        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            tracing_subscriber::registry()
                .with(fmtlayer)
                .with(filter)
                .init();
        }
        #[cfg(feature = "dangerous-crypto-debug")]
        tracing::warn!(
            "Dangerous crypto debug features are enabled. THIS MUST NOT BE USED IN PRODUCTION BUILDS!!"
        );
    });
}

/// Setup the error converter to ensure conversion errors don't cause panics
/// Check [`bitwarden_uniffi_error`] for more details
fn setup_error_converter() {
    bitwarden_uniffi_error::set_error_to_uniffi_error(|e| {
        crate::error::BitwardenError::Conversion(e.to_string()).into()
    });
}

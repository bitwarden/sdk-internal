#![doc = include_str!("../README.md")]

uniffi::setup_scaffolding!();

use std::sync::{Arc, Once};

use auth::AuthClient;
use bitwarden_core::{ClientSettings, client::internal::ClientManagedTokens};

#[allow(missing_docs)]
pub mod auth;
#[allow(missing_docs)]
pub mod crypto;
#[allow(missing_docs)]
pub mod error;
mod log_callback;
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
pub use log_callback::LogCallback;
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
        init_logger(None);
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

/// Initialize the SDK logger
///
/// This function should be called once before creating any SDK clients.
/// It initializes the tracing infrastructure for the SDK and optionally
/// registers a callback to receive log events.
///
/// # Parameters
/// - `callback`: Optional callback to receive SDK log events. Pass `None` to use
///   only platform loggers (oslog on iOS, logcat on Android).
///
/// # Example
/// ```kotlin
/// // Initialize with callback before creating clients
/// initLogger(FlightRecorderCallback())
/// val client = Client(tokenProvider, settings)
/// ```
///
/// # Notes
/// - This function can only be called once - subsequent calls are ignored
/// - If not called explicitly, logging is auto-initialized when first client is created
/// - Platform loggers (oslog/logcat) are always enabled regardless of callback
#[uniffi::export]
pub fn init_logger(callback: Option<Arc<dyn LogCallback>>) {
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

        // Build base registry once instead of duplicating per-platform
        let registry = tracing_subscriber::registry().with(fmtlayer).with(filter);

        // Conditionally add callback layer if provided
        // Use Option to avoid type incompatibility between Some/None branches
        let callback_layer = callback.map(log_callback::CallbackLayer::new);
        let registry = registry.with(callback_layer);
        #[cfg(target_os = "ios")]
        {
            const TAG: &str = "com.8bit.bitwarden";
            registry
                .with(tracing_oslog::OsLogger::new(TAG, "default"))
                .init();
        }

        #[cfg(target_os = "android")]
        {
            const TAG: &str = "com.bitwarden.sdk";
            registry
                .with(
                    tracing_android::layer(TAG)
                        .expect("initialization of android logcat tracing layer"),
                )
                .init();
        }

        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            registry.init();
        }
    });
}

/// Setup the error converter to ensure conversion errors don't cause panics
/// Check [`bitwarden_uniffi_error`] for more details
fn setup_error_converter() {
    bitwarden_uniffi_error::set_error_to_uniffi_error(|e| {
        crate::error::BitwardenError::Conversion(e.to_string()).into()
    });
}
#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    // Mock token provider for testing
    #[derive(Debug)]
    struct MockTokenProvider;

    #[async_trait::async_trait]
    impl ClientManagedTokens for MockTokenProvider {
        async fn get_access_token(&self) -> Option<String> {
            Some("mock_token".to_string())
        }
    }
    /// Mock LogCallback implementation for testing
    struct TestLogCallback {
        logs: Arc<Mutex<Vec<(String, String, String)>>>,
    }
    impl LogCallback for TestLogCallback {
        fn on_log(&self, level: String, target: String, message: String) -> Result<()> {
            self.logs
                .lock()
                .expect("Failed to lock logs mutex")
                .push((level, target, message));
            Ok(())
        }
    }

    // Log callback unit tests only test happy path because running this with
    // Once means we get one registered callback per test run. There are
    // other tests written as integration tests in the /tests/ folder that
    // assert more specific details.
    #[test]
    fn test_callback_receives_logs() {
        let logs = Arc::new(Mutex::new(Vec::new()));
        let callback = Arc::new(TestLogCallback { logs: logs.clone() });

        // Initialize logger with callback before creating client
        init_logger(Some(callback));

        // Create client
        let _client = Client::new(Arc::new(MockTokenProvider), None);

        // Trigger a log
        tracing::info!("test message from SDK");

        // Verify callback received it
        let captured = logs.lock().expect("Failed to lock logs mutex");
        assert!(!captured.is_empty(), "Callback should receive logs");

        // Find our specific test log (there may be other SDK logs during init)
        let test_log = captured
            .iter()
            .find(|(_, _, msg)| msg.contains("test message"))
            .expect("Should find our test log message");

        assert_eq!(test_log.0, "INFO");
        assert!(test_log.2.contains("test message"));
    }
}

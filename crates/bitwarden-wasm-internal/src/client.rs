extern crate console_error_panic_hook;
use std::{fmt::Display, sync::Arc};

use bitwarden_core::ClientSettings;
use bitwarden_error::bitwarden_error;
use bitwarden_pm::{PasswordManagerClient as InnerPasswordManagerClient, clients::*};
use bitwarden_user_crypto_management::UserCryptoManagementClientExt;
use wasm_bindgen::prelude::*;

use crate::platform::{
    PlatformClient,
    token_provider::{JsTokenProvider, WasmClientManagedTokens},
};

#[wasm_bindgen(typescript_custom_section)]
const TOKEN_CUSTOM_TS_TYPE: &'static str = r#"
/**
 * @deprecated Use PasswordManagerClient instead
 */
export type BitwardenClient = PasswordManagerClient;
"#;

/// The main entry point for the Bitwarden SDK in WebAssembly environments
#[wasm_bindgen]
pub struct PasswordManagerClient(pub(crate) InnerPasswordManagerClient);

#[wasm_bindgen]
impl PasswordManagerClient {
    /// Initialize a new instance of the SDK client
    #[wasm_bindgen(constructor)]
    pub fn new(token_provider: JsTokenProvider, settings: Option<ClientSettings>) -> Self {
        let tokens = Arc::new(WasmClientManagedTokens::new(token_provider));
        Self(InnerPasswordManagerClient::new_with_client_tokens(
            settings, tokens,
        ))
    }

    /// Test method, echoes back the input
    pub fn echo(&self, msg: String) -> String {
        msg
    }

    /// Returns the current SDK version
    pub fn version(&self) -> String {
        #[cfg(feature = "bitwarden-license")]
        return format!("COMMERCIAL-{}", env!("SDK_VERSION"));
        #[cfg(not(feature = "bitwarden-license"))]
        return env!("SDK_VERSION").to_owned();
    }

    /// Test method, always throws an error
    pub fn throw(&self, msg: String) -> Result<(), TestError> {
        Err(TestError(msg))
    }

    /// Test method, calls http endpoint
    pub async fn http_get(&self, url: String) -> Result<String, String> {
        let client = self.0.0.internal.get_http_client();
        let res = client.get(&url).send().await.map_err(|e| e.to_string())?;

        res.text().await.map_err(|e| e.to_string())
    }

    /// Auth related operations.
    pub fn auth(&self) -> AuthClient {
        self.0.auth()
    }

    /// Bitwarden licensed operations.
    #[cfg(feature = "bitwarden-license")]
    pub fn commercial(&self) -> bitwarden_pm::CommercialPasswordManagerClient {
        self.0.commercial()
    }

    /// Crypto related operations.
    pub fn crypto(&self) -> CryptoClient {
        self.0.0.crypto()
    }

    /// User crypto management related operations.
    pub fn user_crypto_management(&self) -> UserCryptoManagementClient {
        self.0.0.user_crypto_management()
    }

    /// Vault item related operations.
    pub fn vault(&self) -> VaultClient {
        self.0.vault()
    }

    /// Constructs a specific client for platform-specific functionality
    pub fn platform(&self) -> PlatformClient {
        PlatformClient::new(self.0.0.clone())
    }

    /// Constructs a specific client for generating passwords and passphrases
    pub fn generator(&self) -> GeneratorClient {
        self.0.generator()
    }

    /// Exporter related operations.
    pub fn exporters(&self) -> ExporterClient {
        self.0.exporters()
    }
}

#[bitwarden_error(basic)]
pub struct TestError(String);

impl Display for TestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

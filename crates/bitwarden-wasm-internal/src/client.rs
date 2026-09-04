extern crate console_error_panic_hook;
use std::{fmt::Display, sync::Arc};

use bitwarden_core::{ClientSettings, key_management::state_bridge::StateBridgeClient};
use bitwarden_crypto_sync_handler::CryptoSyncHandlerClient;
use bitwarden_error::bitwarden_error;
use bitwarden_managed_settings::ManagedSettingsClient;
use bitwarden_pm::{PasswordManagerClient as InnerPasswordManagerClient, clients::*};
use bitwarden_policies::PolicyClient;
use bitwarden_user_crypto_management::{UserCryptoManagementClient, UserCryptoManagementClientExt};
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
#[bitwarden_ffi::wasm_object]
pub struct PasswordManagerClient(pub(crate) InnerPasswordManagerClient);

// Every method here hands back a `#[wasm_bindgen]` sub-client handle, so inference is off for the
// block and the one value that does cross via serde is marked.
#[bitwarden_ffi::wasm_export]
impl PasswordManagerClient {
    /// Initialize a new instance of the SDK client
    ///
    /// `managed_settings` is the host-owned handle onto the operating system's Unified Endpoint
    /// Management profile. The client shares its profile, so profiles pushed after construction
    /// are visible here. Pass a fresh `ManagedSettingsClient` where the host has no UEM source.
    #[wasm_bindgen(constructor)]
    pub fn new(
        token_provider: JsTokenProvider,
        settings: Option<ClientSettings>,
        managed_settings: &ManagedSettingsClient,
    ) -> Self {
        let tokens = Arc::new(WasmClientManagedTokens::new(token_provider));
        Self(InnerPasswordManagerClient::new_with_client_tokens(
            settings,
            tokens,
            managed_settings,
        ))
    }

    /// Administrator-enforced settings operations.
    pub fn managed_settings(&self) -> ManagedSettingsClient {
        self.0.managed_settings()
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

    /// Key management operations that run on every sync.
    pub fn crypto_sync_handler(&self) -> CryptoSyncHandlerClient {
        self.0.crypto_sync_handler()
    }

    /// Key management state bridge operations.
    pub fn km_state_bridge(&self) -> StateBridgeClient {
        self.0.0.km_state_bridge()
    }

    /// User crypto management related operations.
    pub fn user_crypto_management(&self) -> UserCryptoManagementClient {
        self.0.0.user_crypto_management()
    }

    /// Vault item related operations.
    pub fn vault(&self) -> VaultClient {
        self.0.vault()
    }

    /// Collection related operations.
    ///
    /// This is registered directly on the top-level client in addition to being nested under
    /// [`vault`](Self::vault). Once consumers have migrated to this accessor, the nested one will
    /// be removed.
    pub fn collections(&self) -> CollectionsClient {
        self.0.collections()
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

    /// Importer related operations.
    pub fn importers(&self) -> ImporterClient {
        self.0.importers()
    }

    /// Policy related operations.
    pub fn policies(&self) -> PolicyClient {
        self.0.policies()
    }

    /// Send related operations.
    pub fn sends(&self) -> SendClient {
        self.0.sends()
    }

    /// Send sync handler operations.
    pub fn send_sync_handler(&self) -> SendSyncHandlerClient {
        self.0.send_sync_handler()
    }

    /// Organization invite link operations.
    pub fn invite_link(&self) -> InviteLinkClient {
        self.0.invite_link()
    }

    /// Crypto cipher suite operations.
    pub fn crypto_cipher_suite(&self) -> CryptoCipherSuiteClient {
        self.0.crypto_cipher_suite()
    }

    /// Whether the client is in Gov Mode.
    pub fn gov_mode(&self) -> bool {
        self.0.0.gov_mode()
    }
}

#[bitwarden_error(basic)]
pub struct TestError(String);

impl Display for TestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

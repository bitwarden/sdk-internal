extern crate console_error_panic_hook;
use std::{fmt::Display, sync::Arc};

use bitwarden_core::{key_management::CryptoClient, Client, ClientSettings};
use bitwarden_error::bitwarden_error;
use bitwarden_exporters::ExporterClientExt;
use bitwarden_generators::GeneratorClientsExt;
use bitwarden_vault::{VaultClient, VaultClientExt};
use wasm_bindgen::prelude::*;

use crate::platform::PlatformClient;

#[allow(missing_docs)]
#[wasm_bindgen]
pub struct BitwardenClient(pub(crate) Client);

#[wasm_bindgen]
impl BitwardenClient {
    #[allow(missing_docs)]
    #[wasm_bindgen(constructor)]
    pub fn new(settings: Option<ClientSettings>, token_provider: JsTokenProvider) -> Self {
        let tokens = Arc::new(WasmClientManagedTokens::new(token_provider));
        Self(Client::new_with_client_tokens(settings, tokens))
    }

    /// Test method, echoes back the input
    pub fn echo(&self, msg: String) -> String {
        msg
    }

    #[allow(missing_docs)]
    pub fn version(&self) -> String {
        env!("SDK_VERSION").to_owned()
    }

    #[allow(missing_docs)]
    pub fn throw(&self, msg: String) -> Result<(), TestError> {
        Err(TestError(msg))
    }

    /// Test method, calls http endpoint
    pub async fn http_get(&self, url: String) -> Result<String, String> {
        let client = self.0.internal.get_http_client();
        let res = client.get(&url).send().await.map_err(|e| e.to_string())?;

        res.text().await.map_err(|e| e.to_string())
    }

    #[allow(missing_docs)]
    pub fn crypto(&self) -> CryptoClient {
        self.0.crypto()
    }

    #[allow(missing_docs)]
    pub fn vault(&self) -> VaultClient {
        self.0.vault()
    }

    /// Constructs a specific client for platform-specific functionality
    pub fn platform(&self) -> PlatformClient {
        PlatformClient::new(self.0.clone())
    }

    /// Constructs a specific client for generating passwords and passphrases
    pub fn generator(&self) -> bitwarden_generators::GeneratorClient {
        self.0.generator()
    }

    #[allow(missing_docs)]
    pub fn exporters(&self) -> bitwarden_exporters::ExporterClient {
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

/// JavaScript-compatible token provider using function closure
#[wasm_bindgen]
pub struct JsTokenProvider {
    get_access_token_fn: js_sys::Function,
}

impl std::fmt::Debug for JsTokenProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsTokenProvider")
            .field("get_access_token_fn", &"<js_function>")
            .finish()
    }
}

#[wasm_bindgen]
impl JsTokenProvider {
    #[wasm_bindgen(constructor)]
    pub fn new(get_access_token_fn: js_sys::Function) -> Self {
        Self {
            get_access_token_fn,
        }
    }
}

/// Wrapper to make JsTokenProvider compatible with ClientManagedTokens
#[derive(Debug)]
struct WasmClientManagedTokens {
    js_provider: JsTokenProvider,
}

impl WasmClientManagedTokens {
    fn new(js_provider: JsTokenProvider) -> Self {
        Self { js_provider }
    }
}

impl bitwarden_core::client::internal::ClientManagedTokens for WasmClientManagedTokens {
    fn get_access_token(&self) -> Option<String> {
        match self
            .js_provider
            .get_access_token_fn
            .call0(&wasm_bindgen::JsValue::UNDEFINED)
        {
            Ok(result) => {
                if result.is_null() || result.is_undefined() {
                    None
                } else {
                    result.as_string()
                }
            }
            Err(_) => None,
        }
    }
}

// SAFETY: JsTokenProvider is only used in WASM context where there's no real threading
unsafe impl Send for WasmClientManagedTokens {}
unsafe impl Sync for WasmClientManagedTokens {}

#[cfg(test)]
#[allow(dead_code)] // Not actually dead, but rust-analyzer doesn't understand `wasm_bindgen_test`
mod tests {
    use super::*;
    use bitwarden_core::client::internal::ClientManagedTokens;
    use wasm_bindgen_test::*;

    // Note: These tests are designed to run in a WASM environment
    // Run with: wasm-pack test --node

    #[wasm_bindgen_test]
    fn test_js_token_provider_creation() {
        // Create a simple function that returns a test token
        let js_fn = js_sys::Function::new_no_args("return 'test-token-123';");
        let provider = JsTokenProvider::new(js_fn);

        // Verify the provider was created successfully
        // This mainly tests the constructor works without panicking
        assert!(format!("{:?}", provider).contains("JsTokenProvider"));
    }

    #[wasm_bindgen_test]
    fn test_wasm_client_managed_tokens_with_valid_token() {
        let js_fn = js_sys::Function::new_no_args("return 'valid-access-token';");
        let provider = JsTokenProvider::new(js_fn);
        let tokens = WasmClientManagedTokens::new(provider);

        let result = tokens.get_access_token();
        assert_eq!(result, Some("valid-access-token".to_string()));
    }

    #[wasm_bindgen_test]
    fn test_wasm_client_managed_tokens_with_null_token() {
        let js_fn = js_sys::Function::new_no_args("return null;");
        let provider = JsTokenProvider::new(js_fn);
        let tokens = WasmClientManagedTokens::new(provider);

        let result = tokens.get_access_token();
        assert_eq!(result, None);
    }

    #[wasm_bindgen_test]
    fn test_wasm_client_managed_tokens_with_undefined_token() {
        let js_fn = js_sys::Function::new_no_args("return undefined;");
        let provider = JsTokenProvider::new(js_fn);
        let tokens = WasmClientManagedTokens::new(provider);

        let result = tokens.get_access_token();
        assert_eq!(result, None);
    }

    #[wasm_bindgen_test]
    fn test_wasm_client_managed_tokens_with_error() {
        let js_fn = js_sys::Function::new_no_args("throw new Error('Token error');");
        let provider = JsTokenProvider::new(js_fn);
        let tokens = WasmClientManagedTokens::new(provider);

        let result = tokens.get_access_token();
        // Should return None when the JS function throws an error
        assert_eq!(result, None);
    }
}

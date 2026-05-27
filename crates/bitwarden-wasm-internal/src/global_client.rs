use bitwarden_core::GlobalClient;
use bitwarden_pm::GlobalPasswordManagerClient as InnerGlobalPasswordManagerClient;
use wasm_bindgen::prelude::*;

/// The main entry point for Global Bitwarden SDK operations in WebAssembly environments
#[wasm_bindgen]
pub struct GlobalPasswordManagerClient(
    #[allow(dead_code)] pub(crate) InnerGlobalPasswordManagerClient,
);

#[wasm_bindgen]
impl GlobalPasswordManagerClient {
    /// Initialize a new instance of the SDK client
    #[wasm_bindgen(constructor)]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self(InnerGlobalPasswordManagerClient(GlobalClient::new()))
    }
}

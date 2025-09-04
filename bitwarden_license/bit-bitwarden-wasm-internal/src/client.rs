use std::sync::Arc;

use bitwarden_core::{Client, ClientSettings};
use bitwarden_wasm_internal::{JsTokenProvider, WasmClientManagedTokens};
use wasm_bindgen::prelude::*;

#[allow(missing_docs)]
#[wasm_bindgen]
pub struct CommercialBitwardenClient(Client);

#[wasm_bindgen]
impl CommercialBitwardenClient {
    #[allow(missing_docs)]
    #[wasm_bindgen(constructor)]
    pub fn new(token_provider: JsTokenProvider, settings: Option<ClientSettings>) -> Self {
        let tokens = Arc::new(WasmClientManagedTokens::new(token_provider));
        Self(Client::new_with_client_tokens(settings, tokens))
    }

    /// Returns the underlying OSS client.
    pub fn oss_client(&self) -> bitwarden_wasm_internal::BitwardenClient {
        bitwarden_wasm_internal::BitwardenClient::new_with_existing_client(self.0.clone())
    }

    /// Test method, echoes back the input
    pub fn echo(&self, msg: String) -> String {
        msg
    }

    #[allow(missing_docs)]
    pub fn version(&self) -> String {
        format!("COMMERCIAL-{}", env!("SDK_VERSION"))
    }
}

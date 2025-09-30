use bitwarden_core::client::internal::ClientManagedTokens;
use bitwarden_threading::ThreadBoundRunner;
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

#[wasm_bindgen(typescript_custom_section)]
const TOKEN_CUSTOM_TS_TYPE: &'static str = r#"
export interface TokenProvider {
    get_access_token(): Promise<string | undefined>;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = TokenProvider)]
    pub type JsTokenProvider;

    #[wasm_bindgen(method)]
    pub async fn get_access_token(this: &JsTokenProvider) -> JsValue;
}

/// Thread-bound runner for JavaScript token provider
pub(crate) struct WasmClientManagedTokens(ThreadBoundRunner<JsTokenProvider>);

impl WasmClientManagedTokens {
    pub fn new(js_provider: JsTokenProvider) -> Self {
        Self(ThreadBoundRunner::new(js_provider))
    }
}

impl std::fmt::Debug for WasmClientManagedTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmClientManagedTokens").finish()
    }
}

#[async_trait::async_trait]
impl ClientManagedTokens for WasmClientManagedTokens {
    async fn get_access_token(&self) -> Option<String> {
        self.0
            .run_in_thread(|c| async move { c.get_access_token().await.as_string() })
            .await
            .unwrap_or_default()
    }
}

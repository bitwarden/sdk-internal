use async_trait::async_trait;
use bitwarden_crypto::{SymmetricCryptoKey, safe::PasswordProtectedKeyEnvelope};
use wasm_bindgen::prelude::*;
use bitwarden_threading::ThreadBoundRunner;

use crate::key_management::{state_bridge::{StateBridge, client::StateBridgeClient}};

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export interface WasmStateBridge {
    set_user_key(user_key: SymmetricKey): Promise<void>;
    get_user_key(): Promise<SymmetricKey | null>;
    clear_user_key(): Promise<void>;

    set_persistent_pin_envelope(pin_envelope: PasswordProtectedKeyEnvelope): Promise<void>;
    get_persistent_pin_envelope(): Promise<PasswordProtectedKeyEnvelope | null>;
    clear_persistent_pin_envelope(): Promise<void>;

    set_ephemeral_pin_envelope(pin_envelope: PasswordProtectedKeyEnvelope): Promise<void>;
    get_ephemeral_pin_envelope(): Promise<PasswordProtectedKeyEnvelope | null>;
    clear_ephemeral_pin_envelope(): Promise<void>;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "WasmStateBridge")]
    pub type RawWasmStateBridge;

    // User key management
    #[wasm_bindgen(method)]
    pub async fn set_user_key(this: &RawWasmStateBridge, user_key: JsValue);
    #[wasm_bindgen(method)]
    pub async fn get_user_key(this: &RawWasmStateBridge) -> Option<JsValue>;
    #[wasm_bindgen(method)]
    pub async fn clear_user_key(this: &RawWasmStateBridge);

    #[wasm_bindgen(method)]
    pub async fn set_persistent_pin_envelope(this: &RawWasmStateBridge, pin_envelope: JsValue);
    #[wasm_bindgen(method)]
    pub async fn get_persistent_pin_envelope(this: &RawWasmStateBridge) -> Option<JsValue>;
    #[wasm_bindgen(method)]
    pub async fn clear_persistent_pin_envelope(this: &RawWasmStateBridge);

    #[wasm_bindgen(method)]
    pub async fn set_ephemeral_pin_envelope(this: &RawWasmStateBridge, pin_envelope: JsValue);
    #[wasm_bindgen(method)]
    pub async fn get_ephemeral_pin_envelope(this: &RawWasmStateBridge) -> Option<JsValue>;
    #[wasm_bindgen(method)]
    pub async fn clear_ephemeral_pin_envelope(this: &RawWasmStateBridge);
}

pub struct WasmStateBridge(ThreadBoundRunner<RawWasmStateBridge>);

#[async_trait(?Send)]
impl StateBridge for WasmStateBridge {
    async fn set_user_key(&mut self, user_key: &SymmetricCryptoKey) {
        let key = user_key.to_owned();
        self.0.run_in_thread(|bridge| async move { bridge.set_user_key(key.into()).await }).await.expect("Failed to set user key");
    }

    async fn get_user_key(&self) -> Option<SymmetricCryptoKey> {
        self.0.run_in_thread(|bridge| async move { bridge.get_user_key().await }).await.expect("Failed to get user key").and_then(|js_value| js_value.try_into().ok())
    }

    async fn clear_user_key(&mut self) {
        self.0.run_in_thread(|bridge| async move { bridge.clear_user_key().await }).await.expect("Failed to clear user key");
    }

    async fn set_persistent_pin_envelope(&mut self, pin_envelope: PasswordProtectedKeyEnvelope) {
        self.0.run_in_thread(|bridge| async move { bridge.set_persistent_pin_envelope(pin_envelope.into()).await }).await.expect("Failed to set persistent pin envelope");
    }

    async fn get_persistent_pin_envelope(&self) -> Option<PasswordProtectedKeyEnvelope> {
        self.0.run_in_thread(|bridge| async move { bridge.get_persistent_pin_envelope().await }).await.expect("Failed to get persistent pin envelope").and_then(|js_value| js_value.try_into().ok())
    }

    async fn clear_persistent_pin_envelope(&mut self) {
        self.0.run_in_thread(|bridge| async move { bridge.clear_persistent_pin_envelope().await }).await.expect("Failed to clear persistent pin envelope");
    }

    async fn set_ephemeral_pin_envelope(&mut self, pin_envelope: PasswordProtectedKeyEnvelope) {
        self.0.run_in_thread(|bridge| async move { bridge.set_ephemeral_pin_envelope(pin_envelope.into()).await }).await.expect("Failed to set ephemeral pin envelope");
    }

    async fn get_ephemeral_pin_envelope(&self) -> Option<PasswordProtectedKeyEnvelope> {
        self.0.run_in_thread(|bridge| async move { bridge.get_ephemeral_pin_envelope().await }).await.expect("Failed to get ephemeral pin envelope").and_then(|js_value| js_value.try_into().ok())
    }

    async fn clear_ephemeral_pin_envelope(&mut self) {
        self.0.run_in_thread(|bridge| async move { bridge.clear_ephemeral_pin_envelope().await }).await.expect("Failed to clear ephemeral pin envelope");
    }
}

#[wasm_bindgen]
#[allow(missing_docs)]
impl StateBridgeClient {
    #[wasm_bindgen(js_name = "registerWasmBridgeImpl")]
    pub async fn register_bridge_impl(
        &self,
        bridge_impl: RawWasmStateBridge,
    ) {
        let mut bridge_slot = self.client.internal.temporary_state_bridge.write().expect("Failed to acquire write lock on temporary state bridge");
        *bridge_slot = Some(Box::new(WasmStateBridge(ThreadBoundRunner::new(bridge_impl))));
    }
}

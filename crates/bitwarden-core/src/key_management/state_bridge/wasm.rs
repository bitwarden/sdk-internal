use async_trait::async_trait;
use bitwarden_crypto::{EncString, SymmetricCryptoKey, safe::PasswordProtectedKeyEnvelope};
use bitwarden_threading::ThreadBoundRunner;
use wasm_bindgen::prelude::*;

use crate::key_management::state_bridge::{StateBridgeClient, StateBridgeImpl};

#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
/**
 * Typescript interface that the state bridge needs to implement. The state bridge
 * is a temporary layer that allows quickly transitioning non-repository shaped
 * state to be accessible from within the SDK.
 */
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

    set_encrypted_pin(encrypted_pin: EncString): Promise<void>;
    get_encrypted_pin(): Promise<EncString | null>;
    clear_encrypted_pin(): Promise<void>;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "WasmStateBridge")]
    pub type RawWasmStateBridge;

    // User key management
    #[wasm_bindgen(method)]
    pub async fn set_user_key(this: &RawWasmStateBridge, user_key: SymmetricCryptoKey);
    #[wasm_bindgen(method)]
    pub async fn get_user_key(this: &RawWasmStateBridge) -> Option<SymmetricCryptoKey>;
    #[wasm_bindgen(method)]
    pub async fn clear_user_key(this: &RawWasmStateBridge);

    #[wasm_bindgen(method)]
    pub async fn set_persistent_pin_envelope(
        this: &RawWasmStateBridge,
        pin_envelope: PasswordProtectedKeyEnvelope,
    );
    #[wasm_bindgen(method)]
    pub async fn get_persistent_pin_envelope(
        this: &RawWasmStateBridge,
    ) -> Option<PasswordProtectedKeyEnvelope>;
    #[wasm_bindgen(method)]
    pub async fn clear_persistent_pin_envelope(this: &RawWasmStateBridge);

    #[wasm_bindgen(method)]
    pub async fn set_ephemeral_pin_envelope(
        this: &RawWasmStateBridge,
        pin_envelope: PasswordProtectedKeyEnvelope,
    );
    #[wasm_bindgen(method)]
    pub async fn get_ephemeral_pin_envelope(
        this: &RawWasmStateBridge,
    ) -> Option<PasswordProtectedKeyEnvelope>;
    #[wasm_bindgen(method)]
    pub async fn clear_ephemeral_pin_envelope(this: &RawWasmStateBridge);

    #[wasm_bindgen(method)]
    pub async fn set_encrypted_pin(this: &RawWasmStateBridge, encrypted_pin: EncString);
    #[wasm_bindgen(method)]
    pub async fn get_encrypted_pin(this: &RawWasmStateBridge) -> Option<EncString>;
    #[wasm_bindgen(method)]
    pub async fn clear_encrypted_pin(this: &RawWasmStateBridge);
}

pub struct WasmStateBridge(ThreadBoundRunner<RawWasmStateBridge>);

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl StateBridgeImpl for WasmStateBridge {
    async fn set_user_key(&self, user_key: SymmetricCryptoKey) {
        let user_key = user_key.to_owned();
        self.0
            .run_in_thread(|bridge| async move { bridge.set_user_key(user_key).await })
            .await
            .expect("Failed to set user key");
    }

    async fn get_user_key(&self) -> Option<SymmetricCryptoKey> {
        self.0
            .run_in_thread(|bridge| async move { bridge.get_user_key().await })
            .await
            .expect("Failed to get user key")
    }

    async fn clear_user_key(&self) {
        self.0
            .run_in_thread(|bridge| async move { bridge.clear_user_key().await })
            .await
            .expect("Failed to clear user key");
    }

    async fn set_persistent_pin_envelope(&self, pin_envelope: PasswordProtectedKeyEnvelope) {
        self.0
            .run_in_thread(|bridge| async move {
                bridge
                    .set_persistent_pin_envelope(pin_envelope)
                    .await
            })
            .await
            .expect("Failed to set persistent pin envelope");
    }

    async fn get_persistent_pin_envelope(&self) -> Option<PasswordProtectedKeyEnvelope> {
        self.0
            .run_in_thread(|bridge| async move { bridge.get_persistent_pin_envelope().await })
            .await
            .expect("Failed to get persistent pin envelope")
    }

    async fn clear_persistent_pin_envelope(&self) {
        self.0
            .run_in_thread(|bridge| async move { bridge.clear_persistent_pin_envelope().await })
            .await
            .expect("Failed to clear persistent pin envelope");
    }

    async fn set_ephemeral_pin_envelope(&self, pin_envelope: PasswordProtectedKeyEnvelope) {
        self.0
            .run_in_thread(|bridge| async move {
                bridge.set_ephemeral_pin_envelope(pin_envelope).await
            })
            .await
            .expect("Failed to set ephemeral pin envelope");
    }

    async fn get_ephemeral_pin_envelope(&self) -> Option<PasswordProtectedKeyEnvelope> {
        self.0
            .run_in_thread(|bridge| async move { bridge.get_ephemeral_pin_envelope().await })
            .await
            .expect("Failed to get ephemeral pin envelope")
    }

    async fn clear_ephemeral_pin_envelope(&self) {
        self.0
            .run_in_thread(|bridge| async move { bridge.clear_ephemeral_pin_envelope().await })
            .await
            .expect("Failed to clear ephemeral pin envelope");
    }

    async fn set_encrypted_pin(&self, encrypted_pin: EncString) {
        self.0
            .run_in_thread(|bridge| async move { bridge.set_encrypted_pin(encrypted_pin).await })
            .await
            .expect("Failed to set encrypted pin");
    }

    async fn get_encrypted_pin(&self) -> Option<EncString> {
        self.0
            .run_in_thread(|bridge| async move { bridge.get_encrypted_pin().await })
            .await
            .expect("Failed to get encrypted pin")
    }

    async fn clear_encrypted_pin(&self) {
        self.0
            .run_in_thread(|bridge| async move { bridge.clear_encrypted_pin().await })
            .await
            .expect("Failed to clear encrypted pin");
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl StateBridgeClient {
    /// Registers a the state bridge implementation provided by the host environment.
    pub fn register_bridge_impl(&self, bridge_impl: RawWasmStateBridge) {
        self.client
            .internal
            .state_bridge
            .register(Box::new(WasmStateBridge(ThreadBoundRunner::new(
                bridge_impl,
            ))));
    }
}

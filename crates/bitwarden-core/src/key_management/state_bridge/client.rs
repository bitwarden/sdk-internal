#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use bitwarden_crypto::{SymmetricCryptoKey, safe::PasswordProtectedKeyEnvelope};

use crate::Client;

#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct StateBridgeClient {
    pub(crate) client: crate::Client,
}

impl Client {
    /// A temporary client to bridge KM state into the SDK.
    pub fn km_state_bridge(&self) -> StateBridgeClient {
        StateBridgeClient {
            client: self.clone(),
        }
    }
}

#[allow(missing_docs)]
impl StateBridgeClient {
    pub async fn set_user_key(&mut self, user_key: &SymmetricCryptoKey) {
        self.client
            .internal
            .temporary_state_bridge
            .write()
            .expect("Failed to acquire write lock on temporary state bridge")
            .as_mut()
            .expect("WasmStateBridge not registered")
            .set_user_key(user_key)
            .await;
    }

    pub async fn get_user_key(&self) -> Option<SymmetricCryptoKey> {
        self.client
            .internal
            .temporary_state_bridge
            .write()
            .expect("Failed to acquire write lock on temporary state bridge")
            .as_mut()
            .expect("WasmStateBridge not registered")
            .get_user_key()
            .await
    }

    pub async fn clear_user_key(&mut self) {
        self.client
            .internal
            .temporary_state_bridge
            .write()
            .expect("Failed to acquire write lock on temporary state bridge")
            .as_mut()
            .expect("WasmStateBridge not registered")
            .clear_user_key()
            .await;
    }

    pub async fn set_persistent_pin_envelope(
        &mut self,
        pin_envelope: PasswordProtectedKeyEnvelope,
    ) {
        self.client
            .internal
            .temporary_state_bridge
            .write()
            .expect("Failed to acquire write lock on temporary state bridge")
            .as_mut()
            .expect("WasmStateBridge not registered")
            .set_persistent_pin_envelope(pin_envelope)
            .await;
    }

    pub async fn get_persistent_pin_envelope(&self) -> Option<PasswordProtectedKeyEnvelope> {
        self.client
            .internal
            .temporary_state_bridge
            .write()
            .expect("Failed to acquire write lock on temporary state bridge")
            .as_mut()
            .expect("WasmStateBridge not registered")
            .get_persistent_pin_envelope()
            .await
    }

    pub async fn clear_persistent_pin_envelope(&mut self) {
        self.client
            .internal
            .temporary_state_bridge
            .write()
            .expect("Failed to acquire write lock on temporary state bridge")
            .as_mut()
            .expect("WasmStateBridge not registered")
            .clear_persistent_pin_envelope()
            .await;
    }

    pub async fn set_ephemeral_pin_envelope(
        &mut self,
        pin_envelope: PasswordProtectedKeyEnvelope,
    ) {
        self.client
            .internal
            .temporary_state_bridge
            .write()
            .expect("Failed to acquire write lock on temporary state bridge")
            .as_mut()
            .expect("WasmStateBridge not registered")
            .set_ephemeral_pin_envelope(pin_envelope)
            .await;
    }

    pub async fn get_ephemeral_pin_envelope(&self) -> Option<PasswordProtectedKeyEnvelope> {
        self.client
            .internal
            .temporary_state_bridge
            .write()
            .expect("Failed to acquire write lock on temporary state bridge")
            .as_mut()
            .expect("WasmStateBridge not registered")
            .get_ephemeral_pin_envelope()
            .await
    }

    pub async fn clear_ephemeral_pin_envelope(&mut self) {
        self.client
            .internal
            .temporary_state_bridge
            .write()
            .expect("Failed to acquire write lock on temporary state bridge")
            .as_mut()
            .expect("WasmStateBridge not registered")
            .clear_ephemeral_pin_envelope()
            .await;
    }
}

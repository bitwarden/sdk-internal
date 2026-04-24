#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use bitwarden_crypto::{
    EncString, SymmetricCryptoKey, safe::PasswordProtectedKeyEnvelope,
};

use crate::Client;

use super::StateBridge;

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
    /// Registers a bridge implementation used to read and write temporary key-management state.
    pub fn register_bridge(&self, bridge_impl: Box<dyn StateBridge + Send + Sync>) {
        let mut bridge_slot = self
            .client
            .internal
            .state_bridge
            .write()
            .expect("Failed to acquire write lock on temporary state bridge");
        *bridge_slot = Some(bridge_impl);
    }

    pub async fn set_user_key(&mut self, user_key: &SymmetricCryptoKey) {
        self.client
            .internal
            .state_bridge
            .write()
            .expect("Failed to acquire write lock on temporary state bridge")
            .as_mut()
            .expect("StateBridge not registered")
            .set_user_key(user_key)
            .await;
    }

    pub async fn get_user_key(&self) -> Option<SymmetricCryptoKey> {
        self.client
            .internal
            .state_bridge
            .write()
            .expect("Failed to acquire write lock on temporary state bridge")
            .as_mut()
                .expect("StateBridge not registered")
            .get_user_key()
            .await
    }

    pub async fn clear_user_key(&mut self) {
        self.client
            .internal
            .state_bridge
            .write()
            .expect("Failed to acquire write lock on temporary state bridge")
            .as_mut()
                .expect("StateBridge not registered")
            .clear_user_key()
            .await;
    }

    pub async fn set_persistent_pin_envelope(
        &mut self,
        pin_envelope: PasswordProtectedKeyEnvelope,
    ) {
        self.client
            .internal
            .state_bridge
            .write()
            .expect("Failed to acquire write lock on temporary state bridge")
            .as_mut()
                .expect("StateBridge not registered")
            .set_persistent_pin_envelope(pin_envelope)
            .await;
    }

    pub async fn get_persistent_pin_envelope(&self) -> Option<PasswordProtectedKeyEnvelope> {
        self.client
            .internal
            .state_bridge
            .write()
            .expect("Failed to acquire write lock on temporary state bridge")
            .as_mut()
                .expect("StateBridge not registered")
            .get_persistent_pin_envelope()
            .await
    }

    pub async fn clear_persistent_pin_envelope(&mut self) {
        self.client
            .internal
            .state_bridge
            .write()
            .expect("Failed to acquire write lock on temporary state bridge")
            .as_mut()
                .expect("StateBridge not registered")
            .clear_persistent_pin_envelope()
            .await;
    }

    pub async fn set_ephemeral_pin_envelope(
        &mut self,
        pin_envelope: PasswordProtectedKeyEnvelope,
    ) {
        self.client
            .internal
            .state_bridge
            .write()
            .expect("Failed to acquire write lock on temporary state bridge")
            .as_mut()
                .expect("StateBridge not registered")
            .set_ephemeral_pin_envelope(pin_envelope)
            .await;
    }

    pub async fn get_ephemeral_pin_envelope(&self) -> Option<PasswordProtectedKeyEnvelope> {
        self.client
            .internal
            .state_bridge
            .write()
            .expect("Failed to acquire write lock on temporary state bridge")
            .as_mut()
                .expect("StateBridge not registered")
            .get_ephemeral_pin_envelope()
            .await
    }

    pub async fn clear_ephemeral_pin_envelope(&mut self) {
        self.client
            .internal
            .state_bridge
            .write()
            .expect("Failed to acquire write lock on temporary state bridge")
            .as_mut()
            .expect("StateBridge not registered")
            .clear_ephemeral_pin_envelope()
            .await;
    }

    pub async fn set_encrypted_pin(&mut self, encrypted_pin: EncString) {
        self.client
            .internal
            .state_bridge
            .write()
            .expect("Failed to acquire write lock on temporary state bridge")
            .as_mut()
            .expect("StateBridge not registered")
            .set_encrypted_pin(encrypted_pin)
            .await;
    }

    pub async fn get_encrypted_pin(&self) -> Option<EncString> {
        self.client
            .internal
            .state_bridge
            .write()
            .expect("Failed to acquire write lock on temporary state bridge")
            .as_mut()
            .expect("StateBridge not registered")
            .get_encrypted_pin()
            .await
    }

    pub async fn clear_encrypted_pin(&mut self) {
        self.client
            .internal
            .state_bridge
            .write()
            .expect("Failed to acquire write lock on temporary state bridge")
            .as_mut()
            .expect("StateBridge not registered")
            .clear_encrypted_pin()
            .await;
    }
}

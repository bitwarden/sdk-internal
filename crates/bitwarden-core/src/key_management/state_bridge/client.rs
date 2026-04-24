#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use bitwarden_crypto::{
    EncString, SymmetricCryptoKey, safe::PasswordProtectedKeyEnvelope,
};

use crate::Client;

use super::StateBridgeImpl;

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
    pub fn register_bridge(&self, bridge_impl: Box<dyn StateBridgeImpl + Send + Sync>) {
        self.client.internal.state_bridge.register(bridge_impl);
    }

    pub async fn set_user_key(&self, user_key: &SymmetricCryptoKey) {
        self.client.internal.state_bridge.set_user_key(user_key).await;
    }

    pub async fn get_user_key(&self) -> Option<SymmetricCryptoKey> {
        self.client.internal.state_bridge.get_user_key().await
    }

    pub async fn clear_user_key(&self) {
        self.client.internal.state_bridge.clear_user_key().await;
    }

    pub async fn set_persistent_pin_envelope(&self, pin_envelope: PasswordProtectedKeyEnvelope) {
        self.client
            .internal
            .state_bridge
            .set_persistent_pin_envelope(pin_envelope)
            .await;
    }

    pub async fn get_persistent_pin_envelope(&self) -> Option<PasswordProtectedKeyEnvelope> {
        self.client
            .internal
            .state_bridge
            .get_persistent_pin_envelope()
            .await
    }

    pub async fn clear_persistent_pin_envelope(&self) {
        self.client
            .internal
            .state_bridge
            .clear_persistent_pin_envelope()
            .await;
    }

    pub async fn set_ephemeral_pin_envelope(&self, pin_envelope: PasswordProtectedKeyEnvelope) {
        self.client
            .internal
            .state_bridge
            .set_ephemeral_pin_envelope(pin_envelope)
            .await;
    }

    pub async fn get_ephemeral_pin_envelope(&self) -> Option<PasswordProtectedKeyEnvelope> {
        self.client
            .internal
            .state_bridge
            .get_ephemeral_pin_envelope()
            .await
    }

    pub async fn clear_ephemeral_pin_envelope(&self) {
        self.client
            .internal
            .state_bridge
            .clear_ephemeral_pin_envelope()
            .await;
    }

    pub async fn set_encrypted_pin(&self, encrypted_pin: EncString) {
        self.client
            .internal
            .state_bridge
            .set_encrypted_pin(encrypted_pin)
            .await;
    }

    pub async fn get_encrypted_pin(&self) -> Option<EncString> {
        self.client.internal.state_bridge.get_encrypted_pin().await
    }

    pub async fn clear_encrypted_pin(&self) {
        self.client.internal.state_bridge.clear_encrypted_pin().await;
    }
}

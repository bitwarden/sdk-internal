use bitwarden_crypto::{EncString, SymmetricCryptoKey, safe::PasswordProtectedKeyEnvelope};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use super::StateBridgeImpl;
use crate::Client;

/// Client for interacting with the key-management state bridge. This is used to read and write
/// state held by the clients
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
    pub fn is_bridge_registered(&self) -> bool {
        self.client.internal.state_bridge.is_registered()
    }

    /// Registers a bridge implementation used to read and write temporary key-management state.
    pub fn register_bridge(&self, bridge_impl: Box<dyn StateBridgeImpl + Send + Sync>) {
        self.client
            .internal
            .state_bridge
            .clone()
            .register(bridge_impl);
    }

    pub async fn set_user_key(&self, user_key: &SymmetricCryptoKey) {
        self.client
            .internal
            .state_bridge
            .set_user_key(user_key)
            .await;
    }

    pub async fn get_user_key(&self) -> Option<SymmetricCryptoKey> {
        self.client
            .internal
            .state_bridge
            .clone()
            .get_user_key()
            .await
    }

    pub async fn clear_user_key(&self) {
        self.client
            .internal
            .state_bridge
            .clone()
            .clear_user_key()
            .await;
    }

    pub async fn set_persistent_pin_envelope(&self, pin_envelope: PasswordProtectedKeyEnvelope) {
        self.client
            .internal
            .state_bridge
            .clone()
            .set_persistent_pin_envelope(pin_envelope)
            .await;
    }

    pub async fn get_persistent_pin_envelope(&self) -> Option<PasswordProtectedKeyEnvelope> {
        self.client
            .internal
            .state_bridge
            .clone()
            .get_persistent_pin_envelope()
            .await
    }

    pub async fn clear_persistent_pin_envelope(&self) {
        self.client
            .internal
            .state_bridge
            .clone()
            .clear_persistent_pin_envelope()
            .await;
    }

    pub async fn set_ephemeral_pin_envelope(&self, pin_envelope: PasswordProtectedKeyEnvelope) {
        self.client
            .internal
            .state_bridge
            .clone()
            .set_ephemeral_pin_envelope(pin_envelope)
            .await;
    }

    pub async fn get_ephemeral_pin_envelope(&self) -> Option<PasswordProtectedKeyEnvelope> {
        self.client
            .internal
            .state_bridge
            .clone()
            .get_ephemeral_pin_envelope()
            .await
    }

    pub async fn clear_ephemeral_pin_envelope(&self) {
        self.client
            .internal
            .state_bridge
            .clone()
            .clear_ephemeral_pin_envelope()
            .await;
    }

    pub async fn set_encrypted_pin(&self, encrypted_pin: EncString) {
        self.client
            .internal
            .state_bridge
            .clone()
            .set_encrypted_pin(encrypted_pin)
            .await;
    }

    pub async fn get_encrypted_pin(&self) -> Option<EncString> {
        self.client
            .internal
            .state_bridge
            .clone()
            .get_encrypted_pin()
            .await
    }

    pub async fn clear_encrypted_pin(&self) {
        self.client
            .internal
            .state_bridge
            .clone()
            .clear_encrypted_pin()
            .await;
    }
}

use bitwarden_crypto::{EncString, SymmetricCryptoKey, safe::PasswordProtectedKeyEnvelope};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use super::StateBridgeImpl;
use crate::{
    Client, key_management::account_cryptographic_state::WrappedAccountCryptographicState,
};

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

impl StateBridgeClient {
    /// Returns true if a state bridge implementation has been registered.
    pub fn is_bridge_registered(&self) -> bool {
        self.client.internal.state_bridge.is_registered()
    }

    /// Registers a bridge implementation used to read and write temporary key-management state.
    pub fn register_bridge(&self, bridge_impl: Box<dyn StateBridgeImpl + Send + Sync>) {
        self.client.internal.state_bridge.register(bridge_impl);
    }

    /// Sets the user-key to client-managed state
    pub async fn set_user_key(&self, user_key: &SymmetricCryptoKey) {
        self.client
            .internal
            .state_bridge
            .set_user_key(user_key)
            .await;
    }

    /// Gets the user-key from client-managed state, if available.
    pub async fn get_user_key(&self) -> Option<SymmetricCryptoKey> {
        self.client.internal.state_bridge.get_user_key().await
    }

    /// Clears the user-key from client-managed state.
    pub async fn clear_user_key(&self) {
        self.client.internal.state_bridge.clear_user_key().await;
    }

    /// Sets the persistent PIN envelope to client-managed state
    pub async fn set_persistent_pin_envelope(&self, pin_envelope: PasswordProtectedKeyEnvelope) {
        self.client
            .internal
            .state_bridge
            .set_persistent_pin_envelope(pin_envelope)
            .await;
    }

    /// Gets the persistent PIN envelope from client-managed state, if available.
    pub async fn get_persistent_pin_envelope(&self) -> Option<PasswordProtectedKeyEnvelope> {
        self.client
            .internal
            .state_bridge
            .get_persistent_pin_envelope()
            .await
    }

    /// Clears the persistent PIN envelope from client-managed state.
    pub async fn clear_persistent_pin_envelope(&self) {
        self.client
            .internal
            .state_bridge
            .clear_persistent_pin_envelope()
            .await;
    }

    /// Sets the ephemeral PIN envelope to client-managed state.
    pub async fn set_ephemeral_pin_envelope(&self, pin_envelope: PasswordProtectedKeyEnvelope) {
        self.client
            .internal
            .state_bridge
            .set_ephemeral_pin_envelope(pin_envelope)
            .await;
    }

    /// Gets the ephemeral PIN envelope from client-managed state, if available.
    pub async fn get_ephemeral_pin_envelope(&self) -> Option<PasswordProtectedKeyEnvelope> {
        self.client
            .internal
            .state_bridge
            .get_ephemeral_pin_envelope()
            .await
    }

    /// Clears the ephemeral PIN envelope from client-managed state.
    pub async fn clear_ephemeral_pin_envelope(&self) {
        self.client
            .internal
            .state_bridge
            .clear_ephemeral_pin_envelope()
            .await;
    }

    /// Sets the encrypted PIN to client-managed state.
    pub async fn set_encrypted_pin(&self, encrypted_pin: EncString) {
        self.client
            .internal
            .state_bridge
            .set_encrypted_pin(encrypted_pin)
            .await;
    }

    /// Gets the encrypted PIN from client-managed state, if available.
    pub async fn get_encrypted_pin(&self) -> Option<EncString> {
        self.client.internal.state_bridge.get_encrypted_pin().await
    }

    /// Clears the encrypted PIN from client-managed state.
    pub async fn clear_encrypted_pin(&self) {
        self.client
            .internal
            .state_bridge
            .clear_encrypted_pin()
            .await;
    }

    /// Sets the account cryptographic state to client-managed state.
    pub async fn set_account_cryptographic_state(&self, state: WrappedAccountCryptographicState) {
        self.client
            .internal
            .state_bridge
            .set_account_cryptographic_state(state)
            .await;
    }

    /// Gets the account cryptographic state from client-managed state, if available.
    pub async fn get_account_cryptographic_state(
        &self,
    ) -> Option<WrappedAccountCryptographicState> {
        self.client
            .internal
            .state_bridge
            .get_account_cryptographic_state()
            .await
    }

    /// Clears the account cryptographic state from client-managed state.
    pub async fn clear_account_cryptographic_state(&self) {
        self.client
            .internal
            .state_bridge
            .clear_account_cryptographic_state()
            .await;
    }
}

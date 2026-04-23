use bitwarden_error::bitwarden_error;
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::UserCryptoManagementClient;

#[derive(Clone, Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
/// Determines where the PIN-protected user key envelope is stored.
pub enum PinLockType {
    /// Store the PIN envelope in persistent client-managed state.
    Persistent,
    /// Store the PIN envelope in ephemeral client-managed state.
    Ephemeral,
}

#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
/// Sub-client for configuring PIN unlock behavior.
pub struct PinSettingsClient {
    pub(crate) client: bitwarden_core::Client,
}

#[derive(Debug, Error)]
#[bitwarden_error(flat)]
/// Errors returned by PIN settings operations.
pub enum PinSettingsError {
    #[error("Failed to set PIN state")]
    /// Failed while enrolling or storing the PIN-protected key envelope.
    SetPinState,
}

impl PinSettingsClient {
    pub(crate) fn new(client: bitwarden_core::Client) -> Self {
        Self { client }
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl PinSettingsClient {
    /// Sets the PIN and stores the generated envelope according to the lock type.
    #[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "setPin"))]
    pub async fn set_pin(&self, pin: String, lock_type: PinLockType) -> Result<(), PinSettingsError> {
        let enroll_pin_response = self
            .client
            .crypto()
            .enroll_pin(pin)
            .map_err(|_| PinSettingsError::SetPinState)?;

        let mut state_bridge = self.client.km_state_bridge();
        state_bridge.clear_persistent_pin_envelope().await;
        state_bridge.clear_ephemeral_pin_envelope().await;

        match lock_type {
            PinLockType::Persistent => {
                state_bridge
                    .set_persistent_pin_envelope(enroll_pin_response.pin_protected_user_key_envelope)
                    .await;
            }
            PinLockType::Ephemeral => {
                state_bridge
                    .set_ephemeral_pin_envelope(enroll_pin_response.pin_protected_user_key_envelope)
                    .await;
            }
        }

        Ok(())
    }

    /// Clears both persistent and ephemeral PIN envelopes.
    #[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "unsetPin"))]
    pub async fn unset_pin(&self) {
        let mut state_bridge = self.client.km_state_bridge();
        state_bridge.clear_persistent_pin_envelope().await;
        state_bridge.clear_ephemeral_pin_envelope().await;
    }

    /// Returns the lock type for the currently configured PIN.
    #[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "getPinLockType"))]
    pub async fn get_pin_lock_type(&self) -> Option<PinLockType> {
        let state_bridge = self.client.km_state_bridge();

        if state_bridge.get_persistent_pin_envelope().await.is_some() {
            return Some(PinLockType::Persistent);
        }

        if state_bridge.get_ephemeral_pin_envelope().await.is_some() {
            return Some(PinLockType::Ephemeral);
        }

        None
    }

    /// Indicates whether a PIN has been configured.
    #[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "isPinSet"))]
    pub async fn is_pin_set(&self) -> bool {
        self.get_pin_lock_type().await.is_some()
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl UserCryptoManagementClient {
    /// Returns the PIN settings sub-client.
    pub fn pin_settings(&self) -> PinSettingsClient {
        PinSettingsClient::new(self.client.clone())
    }
}

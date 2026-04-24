use bitwarden_error::bitwarden_error;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::UserCryptoManagementClient;
use bitwarden_core::key_management::{PinLockType, PinUnlockStatus, PinLockSystem};

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
    /// Sets or updates the account PIN and stores the corresponding unlock state.
    ///
    /// The `lock_type` determines how PIN unlock behaves for this account.
    /// Returns an error when the PIN-protected state cannot be persisted.
    pub async fn set_pin(&self, pin: String, lock_type: bitwarden_core::key_management::PinLockType) -> Result<(), PinSettingsError> {
        PinLockSystem::with_client(&self.client).set_pin(pin, lock_type).await
            .map_err(|_| PinSettingsError::SetPinState)
    }

    /// Unenrolls from PIN-based unlock
    pub async fn unset_pin(&self) {
        PinLockSystem::with_client(&self.client).unset_pin().await
    }

    /// Returns the current status of PIN unlock
    pub async fn get_status(&self) -> PinUnlockStatus {
        PinLockSystem::with_client(&self.client).get_pin_status().await
    }

    /// Returns the configured PIN lock type, if a PIN lock is set.
    pub async fn get_lock_type(&self) -> Option<PinLockType> {
        PinLockSystem::with_client(&self.client).get_pin_lock_type().await
    }

    /// Validates whether `pin` matches the currently configured unlock PIN.
    pub async fn validate_pin(&self, pin: String) -> bool {
        PinLockSystem::with_client(&self.client).validate_pin(pin).await
    }

    /// Returns the currently configured PIN, if available.
    pub async fn get_pin(&self) -> Option<String> {
        PinLockSystem::with_client(&self.client).get_pin().await
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl UserCryptoManagementClient {
    /// Returns the PIN settings sub-client.
    pub fn pin_settings(&self) -> PinSettingsClient {
        PinSettingsClient::new(self.client.clone())
    }
}

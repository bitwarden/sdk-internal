use bitwarden_error::bitwarden_error;
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::UserCryptoManagementClient;


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

}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl UserCryptoManagementClient {
    /// Returns the PIN settings sub-client.
    pub fn pin_settings(&self) -> PinSettingsClient {
        PinSettingsClient::new(self.client.clone())
    }
}

use serde::{Deserialize, Serialize};

use super::LoginDeviceRequest;

/// The common bucket of login fields to be re-used across all login mechanisms
/// (e.g., password, SSO, etc.). This will include handling client_id and 2FA.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))] // add mobile support
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)] // add wasm support
pub struct LoginRequest {
    /// OAuth client identifier
    pub client_id: String,

    /// Device information for this login request
    pub device: LoginDeviceRequest,
    // TODO: add two factor support
    // Two-factor authentication
    // pub two_factor: Option<TwoFactorRequest>,
}

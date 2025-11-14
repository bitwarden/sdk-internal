use bitwarden_core::DeviceType;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Device information for login requests.
/// This is common across all login mechanisms and describes the device
/// making the authentication request.
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))] // add mobile support
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)] // add wasm support
pub struct LoginDeviceRequest {
    /// The type of device making the login request
    pub device_type: DeviceType,

    /// Unique identifier for the device
    pub device_identifier: String,

    /// Human-readable name of the device
    pub device_name: String,
}

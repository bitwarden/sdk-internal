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
    /// Note: today, we already have the DeviceType on the ApiConfigurations
    /// but we do not have the other device fields so we will accept the device data at login time
    /// for now. In the future, we might refactor the unauthN client to instantiate with full
    /// device info which would deprecate this struct. However, using the device_type here
    /// allows us to avoid any timing issues in scenarios where the device type could change
    /// between client instantiation and login (unlikely but possible).
    pub device_type: DeviceType,

    /// Unique identifier for the device
    pub device_identifier: String,

    /// Human-readable name of the device
    pub device_name: String,

    /// Push notification token for the device (only for mobile devices)
    pub device_push_token: Option<String>,
}

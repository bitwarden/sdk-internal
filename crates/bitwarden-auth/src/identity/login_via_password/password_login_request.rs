use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::identity::{login_via_password::PasswordPreloginData, models::LoginRequest};

/// Public SDK request model for logging in via password
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))] // add mobile support
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)] // add wasm support
pub struct PasswordLoginRequest {
    /// Common login request fields
    pub login_request: LoginRequest,

    /// User's email address
    pub email: String,
    /// User's master password
    pub password: String,

    /// Prelogin data required for password authentication
    /// (e.g., KDF configuration for deriving the master key)
    pub prelogin_data: PasswordPreloginData,
}

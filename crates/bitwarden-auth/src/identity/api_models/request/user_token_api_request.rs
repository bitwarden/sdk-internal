use bitwarden_core::DeviceType;
use serde::{Deserialize, Serialize};

use crate::api::enums::{GrantType, Scope, TwoFactorProvider};

/// The common payload properties to send to the /connect/token endpoint to obtain
/// tokens for a BW user. This is intended to be flattened into other api requests
/// that represent specific login mechanisms (e.g., password, SSO, etc)
/// in order to avoid duplication of common OAuth fields and custom BW fields.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct UserTokenApiRequest {
    // Standard OAuth2 fields
    /// The client ID for the SDK consuming client.
    /// Note: snake_case is intentional to match the API expectations.
    pub(crate) client_id: String,

    /// The grant type for the token request.
    /// Note: snake_case is intentional to match the API expectations.
    pub(crate) grant_type: GrantType,

    /// The scope for the token request.
    pub(crate) scope: Scope,

    // Custom fields BW uses for user token requests
    /// The device type making the request.
    #[serde(rename = "deviceType")]
    device_type: DeviceType,

    /// The identifier of the device.
    #[serde(rename = "deviceIdentifier")]
    device_identifier: String,

    /// The name of the device.
    #[serde(rename = "deviceName")]
    device_name: String,

    // Two-factor authentication fields
    /// The two-factor authentication token.
    #[serde(rename = "twoFactorToken")]
    two_factor_token: Option<String>,

    /// The two-factor authentication provider.
    #[serde(rename = "twoFactorProvider")]
    two_factor_provider: Option<TwoFactorProvider>,

    /// Whether to remember two-factor authentication on this device.
    #[serde(rename = "twoFactorRemember")]
    two_factor_remember: Option<bool>,
}

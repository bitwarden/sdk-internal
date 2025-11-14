use bitwarden_core::DeviceType;
use serde::{Deserialize, Serialize};

use crate::api::enums::{GrantType, Scope, TwoFactorProvider, scopes_to_string};

/// Standard scopes for user token requests: "api offline_access"
pub(crate) const STANDARD_USER_SCOPES: &[Scope] = &[Scope::Api, Scope::OfflineAccess];

/// The common payload properties to send to the /connect/token endpoint to obtain
/// tokens for a BW user. This is intended to be flattened into other api requests
/// that represent specific login mechanisms (e.g., password, SSO, etc)
/// in order to avoid duplication of common OAuth fields and custom BW fields.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct UserTokenApiRequest {
    // Standard OAuth2 fields
    /// The client ID for the SDK consuming client.
    /// Note: snake_case is intentional to match the API expectations.
    pub client_id: String,

    /// The grant type for the token request.
    /// Note: snake_case is intentional to match the API expectations.
    pub grant_type: GrantType,

    /// The space-separated scopes for the token request (e.g., "api offline_access").
    pub scope: String,

    // Custom fields BW uses for user token requests
    /// The device type making the request.
    #[serde(rename = "deviceType")]
    pub device_type: DeviceType,

    /// The identifier of the device.
    #[serde(rename = "deviceIdentifier")]
    pub device_identifier: String,

    /// The name of the device.
    #[serde(rename = "deviceName")]
    pub device_name: String,

    // Two-factor authentication fields
    /// The two-factor authentication token.
    #[serde(rename = "twoFactorToken")]
    pub two_factor_token: Option<String>,

    /// The two-factor authentication provider.
    #[serde(rename = "twoFactorProvider")]
    pub two_factor_provider: Option<TwoFactorProvider>,

    /// Whether to remember two-factor authentication on this device.
    #[serde(rename = "twoFactorRemember")]
    pub two_factor_remember: Option<bool>,
}

impl UserTokenApiRequest {
    /// Creates a new UserTokenApiRequest with standard scopes ("api offline_access").
    /// The scope can be overridden after construction if needed for specific auth flows.
    pub(crate) fn new(
        client_id: String,
        grant_type: GrantType,
        device_type: DeviceType,
        device_identifier: String,
        device_name: String,
    ) -> Self {
        Self {
            client_id,
            grant_type,
            scope: scopes_to_string(STANDARD_USER_SCOPES),
            device_type,
            device_identifier,
            device_name,
            two_factor_token: None,
            two_factor_provider: None,
            two_factor_remember: None,
        }
    }
}

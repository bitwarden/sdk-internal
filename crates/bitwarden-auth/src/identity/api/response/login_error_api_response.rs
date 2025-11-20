use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "snake_case")]
pub enum PasswordInvalidGrantError {
    InvalidUsernameOrPassword,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "snake_case")]
pub enum InvalidGrantError {
    // Password grant specific errors
    Password(PasswordInvalidGrantError),

    // TODO: other grant specific errors can go here
    /// Fallback for unknown variants for forward compatibility
    #[serde(other)]
    Unknown,
}

/// Per RFC 6749 Section 5.2, these are the standard error responses for OAuth 2.0 token requests.
/// https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "snake_case")]
#[serde(tag = "error")]
pub enum OAuth2ErrorApiResponse {
    /// Invalid request error, typically due to missing parameters for a specific
    /// credential flow. Ex. `password` is required.
    InvalidRequest {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "wasm", tsify(optional))]
        /// The optional error description for invalid request errors.
        error_description: Option<String>,
    },

    /// Invalid grant error, typically due to invalid credentials.
    InvalidGrant {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "wasm", tsify(optional))]
        /// The optional error description for invalid grant errors.
        error_description: Option<InvalidGrantError>,
    },

    /// Invalid client error, typically due to an invalid client secret or client ID.
    InvalidClient {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "wasm", tsify(optional))]
        /// The optional error description for invalid client errors.
        error_description: Option<String>,
    },

    /// Unauthorized client error, typically due to an unauthorized client.
    UnauthorizedClient {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "wasm", tsify(optional))]
        /// The optional error description for unauthorized client errors.
        error_description: Option<String>,
    },

    /// Unsupported grant type error, typically due to an unsupported credential flow.
    /// Note: during initial feature rollout, this will be used to indicate that the
    /// feature flag is disabled.
    UnsupportedGrantType {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "wasm", tsify(optional))]
        /// The optional error description for unsupported grant type errors.
        error_description: Option<String>,
    },

    /// Invalid scope error, typically due to an invalid scope requested.
    InvalidScope {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "wasm", tsify(optional))]
        /// The optional error description for invalid scope errors.
        error_description: Option<String>,
    },

    /// Invalid target error which is shown if the requested
    /// resource is invalid, missing, unknown, or malformed.
    InvalidTarget {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        #[cfg_attr(feature = "wasm", tsify(optional))]
        /// The optional error description for invalid target errors.
        error_description: Option<String>,
    },
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum LoginErrorApiResponse {
    OAuth2Error(OAuth2ErrorApiResponse),
    UnexpectedError(String),
}

// This is just a utility function so that the ? operator works correctly without manual mapping
impl From<reqwest::Error> for LoginErrorApiResponse {
    fn from(value: reqwest::Error) -> Self {
        Self::UnexpectedError(format!("{value:?}"))
    }
}

use std::fmt::Debug;

use crate::send_access::api::{SendAccessTokenApiErrorResponse, SendAccessTokenApiSuccessResponse};

/// A send access token which can be used to access a send.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug)]
pub struct SendAccessTokenResponse {
    /// The actual token string.
    pub token: String,
    /// The timestamp in milliseconds when the token expires.
    pub expires_at: i64,
}

impl From<SendAccessTokenApiSuccessResponse> for SendAccessTokenResponse {
    fn from(response: SendAccessTokenApiSuccessResponse) -> Self {
        // We want to convert the expires_in from seconds to a millisecond timestamp to have a
        // concrete time the token will expire as it is easier to build logic around a
        // concrete time rather than a duration.
        let expires_at =
            chrono::Utc::now().timestamp_millis() + (response.expires_in * 1000) as i64;

        SendAccessTokenResponse {
            token: response.access_token,
            expires_at,
        }
    }
}

// We're using the full variant of the bitwarden-error macro because we want to keep the contents of
// SendAccessTokenApiErrorResponse
#[bitwarden_error::bitwarden_error(full)]
#[derive(Debug, thiserror::Error)]
#[serde(tag = "kind", content = "data", rename_all = "lowercase")]
/// Represents errors that can occur when requesting a send access token.
/// It includes expected and unexpected API errors.
pub enum SendAccessTokenError {
    #[error("Unexpected Error response: {0:?}")]
    /// Represents an unexpected error that occurred during the request.
    /// This would typically be a transport-level error, such as network issues or serialization
    /// problems.
    Unexpected(UnexpectedIdentityError),

    #[error("Expected error response")]
    /// Represents an expected error response from the API.
    Expected(SendAccessTokenApiErrorResponse),
}

// This is just a utility function so that the ? operator works correctly without manual mapping
impl From<reqwest::Error> for SendAccessTokenError {
    fn from(value: reqwest::Error) -> Self {
        Self::Unexpected(UnexpectedIdentityError(format!("{value:?}")))
    }
}

/// Any unexpected error that occurs when making requests to identity. This could be
/// local/transport/decoding failure from the HTTP client (DNS/TLS/connect/read timeout,
/// connection reset, or JSON decode failure on a success response) or non-2xx response with an
/// unexpected body or status. Used when decoding the server's error payload into
/// `SendAccessTokenApiErrorResponse` fails, or for 5xx responses where no structured error is
/// available.
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct UnexpectedIdentityError(pub String);

// Newtype wrapper for unexpected identity errors for uniffi compatibility.
#[cfg(feature = "uniffi")] // only compile this when uniffi feature is enabled
uniffi::custom_newtype!(UnexpectedIdentityError, String);

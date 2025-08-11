use std::fmt::Debug;

use crate::send_access::api::{SendAccessTokenApiErrorResponse, SendAccessTokenApiSuccessResponse};

/// A send access token which can be used to access a send.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
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

#[allow(missing_docs)]
// We're using the full variant of the bitwarden-error macro because we want to keep the contents of
// SendAccessTokenApiErrorResponse
#[bitwarden_error::bitwarden_error(full)]
#[derive(Debug, thiserror::Error)]
pub enum SendAccessTokenError {
    #[error("API Error: {0:?}")]
    Api(AuthApiError),

    #[error("Send access token error response")]
    Response(SendAccessTokenApiErrorResponse),
}

// This is just a utility function so that the ? operator works correctly without manual mapping
impl From<reqwest::Error> for SendAccessTokenError {
    fn from(value: reqwest::Error) -> Self {
        Self::Api(AuthApiError(value))
    }
}

// This wrapper needs to exist because the `bitwarden_error(full)` macro requires every variant to
// implement serialize+tsify, which is not the case for the `Api` variant. We only really care about
// the contents of the `Response` variant, so ideally the macro would support a way of marking the
// `Api` variant somehow so it gets serialized as a plain string.
// As that is not the case, we have to implement it manually.

#[derive(Debug)]
pub struct AuthApiError(reqwest::Error);

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export type AuthApiError = string;
"#;

impl serde::Serialize for AuthApiError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("{:?}", self.0))
    }
}

impl<'de> serde::Deserialize<'de> for AuthApiError {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Err(serde::de::Error::custom("deserialization not supported"))
    }
}

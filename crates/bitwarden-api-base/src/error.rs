//! Error types for API operations.

use std::{convert::Infallible, error, fmt, marker::PhantomData};

use serde::{Deserialize, Serialize};

/// Response content from a failed API call.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ResponseContent {
    /// HTTP status code of the response.
    #[serde(with = "crate::status_code_serializer")]
    pub status: reqwest::StatusCode,
    /// Response body content.
    pub message: String,
}

/// Errors that can occur during API operations.
///
/// This type is intentionally not exposed over UniFFI. It is always wrapped into
/// `bitwarden_core::ApiError` before crossing the FFI boundary, and that type carries the
/// `uniffi::Error` derive. Deriving `uniffi::Error` here as well would export a second error type
/// named `Error`, which collides with the `Swift.Error` protocol in the generated Swift bindings.
#[derive(Debug)]
pub enum Error<T = ()> {
    /// Error from the reqwest HTTP client.
    Reqwest(reqwest::Error),
    /// Error from the reqwest middleware.
    ReqwestMiddleware(reqwest_middleware::Error),
    /// JSON serialization/deserialization error.
    Serde(serde_json::Error),
    /// I/O error.
    Io(std::io::Error),
    /// API returned an error response.
    Response(ResponseContent),

    /// Phantom variant to keep the unused `T` parameter alive without affecting downstream
    /// `impl<T> From<Error<T>> for FooError` impls. Uninhabited via [`Infallible`].
    #[doc(hidden)]
    _Phantom(PhantomData<T>, Infallible),
}

impl<T> fmt::Display for Error<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (module, e) = match self {
            Error::Reqwest(e) => ("reqwest", e.to_string()),
            Error::ReqwestMiddleware(e) => ("reqwest-middleware", e.to_string()),
            Error::Serde(e) => ("serde", e.to_string()),
            Error::Io(e) => ("IO", e.to_string()),
            Error::Response(e) => ("response", format!("status code {}", e.status)),
            Error::_Phantom(_, _) => unreachable!(),
        };
        write!(f, "error in {}: {}", module, e)
    }
}

impl<T: fmt::Debug> error::Error for Error<T> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        Some(match self {
            Error::Reqwest(e) => e,
            Error::ReqwestMiddleware(e) => e,
            Error::Serde(e) => e,
            Error::Io(e) => e,
            Error::Response(_) | Error::_Phantom(_, _) => return None,
        })
    }
}

impl<T> From<reqwest::Error> for Error<T> {
    fn from(e: reqwest::Error) -> Self {
        Error::Reqwest(e)
    }
}

impl<T> From<reqwest_middleware::Error> for Error<T> {
    fn from(e: reqwest_middleware::Error) -> Self {
        Error::ReqwestMiddleware(e)
    }
}

impl<T> From<serde_json::Error> for Error<T> {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e)
    }
}

impl<T> From<std::io::Error> for Error<T> {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl<T> From<ResponseContent> for Error<T> {
    fn from(value: ResponseContent) -> Self {
        Self::Response(value)
    }
}

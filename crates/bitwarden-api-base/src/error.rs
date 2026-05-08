//! Error types for API operations.

use std::{error, fmt};

/// Response content from a failed API call.
#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ResponseContent {
    /// HTTP status code of the response.
    pub status: u16,
    /// Response body content.
    pub message: String,
}

impl ResponseContent {
    /// Constructs a [ResponseContent] from a [reqwest::StatusCode] and message.
    pub fn new(status: reqwest::StatusCode, message: String) -> Self {
        Self {
            status: status.as_u16(),
            message,
        }
    }
}

/// Errors that can occur during API operations.
#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
pub enum Error {
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
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (module, e) = match self {
            Error::Reqwest(e) => ("reqwest", e.to_string()),
            Error::ReqwestMiddleware(e) => ("reqwest-middleware", e.to_string()),
            Error::Serde(e) => ("serde", e.to_string()),
            Error::Io(e) => ("IO", e.to_string()),
            Error::Response(e) => ("response", format!("status code {}", e.status)),
        };
        write!(f, "error in {}: {}", module, e)
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        Some(match self {
            Error::Reqwest(e) => e,
            Error::ReqwestMiddleware(e) => e,
            Error::Serde(e) => e,
            Error::Io(e) => e,
            Error::Response(_) => return None,
        })
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Reqwest(e)
    }
}

impl From<reqwest_middleware::Error> for Error {
    fn from(e: reqwest_middleware::Error) -> Self {
        Error::ReqwestMiddleware(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<ResponseContent> for Error {
    fn from(value: ResponseContent) -> Self {
        Self::Response(value)
    }
}

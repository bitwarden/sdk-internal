//! Error types for API operations.

use std::{error, fmt};

/// Response content from a failed API call.
#[derive(Debug)]
pub struct ResponseContent<T> {
    /// HTTP status code of the response.
    pub status: reqwest::StatusCode,
    /// Raw response body content.
    pub content: String,
    /// Deserialized entity from the response.
    pub entity: Option<T>,
}

/// Errors that can occur during API operations.
#[derive(Debug)]
pub enum Error<T> {
    /// Error from the reqwest HTTP client.
    Reqwest(reqwest::Error),
    /// Error from the reqwest middleware.
    ReqwestMiddleware(reqwest_middleware::Error),
    /// JSON serialization/deserialization error.
    Serde(serde_json::Error),
    /// I/O error.
    Io(std::io::Error),
    /// API returned an error response.
    ResponseError(ResponseContent<T>),
}

impl<T> fmt::Display for Error<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (module, e) = match self {
            Error::Reqwest(e) => ("reqwest", e.to_string()),
            Error::ReqwestMiddleware(e) => ("reqwest-middleware", e.to_string()),
            Error::Serde(e) => ("serde", e.to_string()),
            Error::Io(e) => ("IO", e.to_string()),
            Error::ResponseError(e) => ("response", format!("status code {}", e.status)),
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
            Error::ResponseError(_) => return None,
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

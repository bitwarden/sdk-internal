//! Error types for the Play test framework

use thiserror::Error;

/// Errors that can occur during Play framework operations
#[derive(Debug, Error)]
pub enum PlayError {
    /// HTTP request failed
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Server returned an error response
    #[error("Server error [{status}]: {body}")]
    ServerError {
        /// HTTP status code
        status: u16,
        /// Response body
        body: String,
    },
}

/// Result type for Play framework operations
pub type PlayResult<T> = Result<T, PlayError>;

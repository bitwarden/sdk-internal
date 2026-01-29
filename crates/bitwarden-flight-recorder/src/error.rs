//! Error types for Flight Recorder operations.

use bitwarden_error::bitwarden_error;
use thiserror::Error;

/// Errors that can occur during Flight Recorder operations.
/// These are errors in the logging infrastructure itself, NOT application errors being logged.
#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum FlightRecorderError {
    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Flight Recorder not initialized
    #[error("Flight Recorder not initialized - call init_sdk first")]
    NotInitialized,

    /// Storage operation failed
    #[error("Storage operation failed: {0}")]
    Storage(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type for Flight Recorder operations
pub type Result<T> = std::result::Result<T, FlightRecorderError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = FlightRecorderError::NotInitialized;
        assert!(err.to_string().contains("not initialized"));
    }

    #[test]
    fn test_storage_error_display() {
        let err = FlightRecorderError::Storage("disk full".to_string());
        assert!(err.to_string().contains("disk full"));
    }

    #[test]
    fn test_internal_error_display() {
        let err = FlightRecorderError::Internal("unexpected state".to_string());
        assert!(err.to_string().contains("unexpected state"));
    }
}

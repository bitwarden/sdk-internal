/// Errors that can occur during cookie storage operations.
///
/// Provides structured error types with explicit variants for matchable error recovery.
/// See ADR-050 for rationale on using thiserror over anyhow.
#[derive(Debug, thiserror::Error)]
pub enum CookieError {
    /// Cookie storage backend operation failed (file I/O, database error, etc.)
    #[error("Cookie storage operation failed: {0}")]
    StorageFailure(String),

    /// Cookie has invalid format or attributes
    #[error("Invalid cookie format or attributes: {0}")]
    InvalidCookie(String),

    /// Cookie storage quota exceeded (max cookies stored)
    #[error("Cookie storage quota exceeded")]
    QuotaExceeded,

    /// Cookie not found by name
    #[error("Cookie not found: {name}")]
    NotFound {
        /// Name of the cookie that was not found
        name: String,
    },

    /// Cookie violates security policy (e.g., Secure=true on chrome-extension://)
    #[error("Cookie security policy violation: {0}")]
    SecurityViolation(String),
}

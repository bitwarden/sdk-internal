//! Error type for the 1Password client.
//!
//! The codes noted below are 1Password server error codes.

use thiserror::Error;

/// Errors returned by the 1Password access library.
#[derive(Debug, Error)]
pub enum OnePasswordError {
    /// Network or transport failure.
    #[error("network error: {0}")]
    Network(String),

    /// Invalid username, password, or Secret Key (1Password code 102).
    #[error("invalid credentials")]
    BadCredentials,

    /// The requested resource was not found (1Password code 117).
    #[error("not found")]
    NotFound,

    /// The account requires two-factor authentication to continue.
    #[error("two-factor authentication required")]
    TwoFactorRequired,

    /// A submitted two-factor code was rejected.
    #[error("two-factor authentication failed")]
    TwoFactorFailed,

    /// Decryption of a server payload failed.
    #[error("decryption failed")]
    Decryption,

    /// A server response could not be parsed.
    #[error("failed to parse server response")]
    Parse,

    /// An item, category, or auth method that is not supported yet.
    #[error("unsupported: {0}")]
    Unsupported(String),

    /// An invariant was violated: malformed input, a size mismatch, or a "should not happen" case.
    #[error("internal error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_describe_themselves() {
        assert_eq!(
            OnePasswordError::Network("timed out".into()).to_string(),
            "network error: timed out"
        );
        assert_eq!(
            OnePasswordError::Unsupported("Duo".into()).to_string(),
            "unsupported: Duo"
        );
        assert_eq!(
            OnePasswordError::BadCredentials.to_string(),
            "invalid credentials"
        );
    }
}

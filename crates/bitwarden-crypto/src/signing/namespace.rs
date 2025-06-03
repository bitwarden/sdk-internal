use crate::{error::SignatureError, CryptoError};

/// Signing is domain-separated within bitwarden, to prevent cross protocol attacks.
///
/// A new signed entity or protocol shall use a new signing namespace. Generally, this means
/// that a signing namespace has exactly one associated valid message struct.
///
/// If there is a new version of a message added, it should (generally) use a new namespace, since
/// this prevents downgrades to the old type of message, and makes optional fields unnecessary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningNamespace {
    /// The namespace for
    /// [`SignedPublicKey`](crate::keys::SignedPublicKey).
    SignedPublicKey = 1,
    /// This namespace is only used in tests and documentation.
    ExampleNamespace = -1,
    /// This namespace is only used in tests and documentation.
    ExampleNamespace2 = -2,
}

impl SigningNamespace {
    /// Returns the numeric value of the namespace.
    pub fn as_i64(&self) -> i64 {
        *self as i64
    }

    /// Converts an i64 value to a `SigningNamespace`, and fails if there is no corresponding
    /// namespace for the value.
    pub fn try_from_i64(value: i64) -> Result<Self, CryptoError> {
        match value {
            1 => Ok(Self::SignedPublicKey),
            -1 => Ok(Self::ExampleNamespace),
            -2 => Ok(Self::ExampleNamespace2),
            _ => Err(SignatureError::InvalidNamespace.into()),
        }
    }
}

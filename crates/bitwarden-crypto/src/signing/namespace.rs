use crate::{error::SignatureError, CryptoError};

/// Signing is domain-separated within bitwarden, to prevent cross protocol attacks.
///
/// A new signed entity or protocol shall use a new signing namespace. Generally, this means
/// that a signing namespace has exactly one associated valid message struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningNamespace {
    /// The namespace for
    /// [`PublicKeyOwnershipClaim`](crate::signing::claims::PublicKeyOwnershipClaim).
    PublicKeyOwnershipClaim = 1,
    /// This namespace is only used in tests and documentation.
    ExampleNamespace = -1,
}

impl SigningNamespace {
    pub fn as_i64(&self) -> i64 {
        *self as i64
    }

    pub fn try_from_i64(value: i64) -> Result<Self, CryptoError> {
        match value {
            1 => Ok(Self::PublicKeyOwnershipClaim),
            -1 => Ok(Self::ExampleNamespace),
            _ => Err(SignatureError::InvalidNamespace.into()),
        }
    }
}

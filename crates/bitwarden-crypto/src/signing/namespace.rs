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
    #[cfg(test)]
    ExampleNamespace = -1,
    /// This namespace is only used in tests and documentation.
    #[cfg(test)]
    ExampleNamespace2 = -2,
}

impl SigningNamespace {
    /// Returns the numeric value of the namespace.
    pub fn as_i64(&self) -> i64 {
        *self as i64
    }
}

impl TryFrom<i64> for SigningNamespace {
    type Error = CryptoError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(SigningNamespace::SignedPublicKey),
            -1 => Ok(SigningNamespace::ExampleNamespace),
            -2 => Ok(SigningNamespace::ExampleNamespace2),
            _ => Err(SignatureError::InvalidNamespace.into()),
        }
    }
}

impl TryFrom<i128> for SigningNamespace {
    type Error = CryptoError;

    fn try_from(value: i128) -> Result<Self, Self::Error> {
        if value < i64::MIN as i128 || value > i64::MAX as i128 {
            return Err(SignatureError::InvalidNamespace.into());
        }
        Self::try_from(value as i64)
    }
}

use crate::{CryptoError, error::SignatureError};

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
    /// The namespace for SignedSecurityState
    SecurityState = 2,
    /// This namespace is only used in tests
    #[cfg(test)]
    ExampleNamespace = -1,
    /// This namespace is only used in tests
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
            2 => Ok(SigningNamespace::SecurityState),
            #[cfg(test)]
            -1 => Ok(SigningNamespace::ExampleNamespace),
            #[cfg(test)]
            -2 => Ok(SigningNamespace::ExampleNamespace2),
            _ => Err(SignatureError::InvalidNamespace.into()),
        }
    }
}

impl TryFrom<i128> for SigningNamespace {
    type Error = CryptoError;

    fn try_from(value: i128) -> Result<Self, Self::Error> {
        let Ok(value) = i64::try_from(value) else {
            return Err(SignatureError::InvalidNamespace.into());
        };
        Self::try_from(value)
    }
}

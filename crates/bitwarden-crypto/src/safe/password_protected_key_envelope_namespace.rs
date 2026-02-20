use crate::{cose::ContentNamespace, safe::PasswordProtectedKeyEnvelopeError};

/// The content-layer separation namespace for password protected key envelopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordProtectedKeyEnvelopeNamespace {
    /// The namespace for unlocking vaults with a PIN.
    PinUnlock = 1,
    /// This namespace is only used in tests
    #[cfg(test)]
    ExampleNamespace = -1,
    /// This namespace is only used in tests
    #[cfg(test)]
    ExampleNamespace2 = -2,
}

impl PasswordProtectedKeyEnvelopeNamespace {
    /// Returns the numeric value of the namespace.
    pub fn as_i64(&self) -> i64 {
        *self as i64
    }
}

impl TryFrom<i64> for PasswordProtectedKeyEnvelopeNamespace {
    type Error = PasswordProtectedKeyEnvelopeError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(PasswordProtectedKeyEnvelopeNamespace::PinUnlock),
            #[cfg(test)]
            -1 => Ok(PasswordProtectedKeyEnvelopeNamespace::ExampleNamespace),
            #[cfg(test)]
            -2 => Ok(PasswordProtectedKeyEnvelopeNamespace::ExampleNamespace2),
            _ => Err(PasswordProtectedKeyEnvelopeError::InvalidNamespace),
        }
    }
}

impl TryFrom<i128> for PasswordProtectedKeyEnvelopeNamespace {
    type Error = PasswordProtectedKeyEnvelopeError;

    fn try_from(value: i128) -> Result<Self, Self::Error> {
        let Ok(value) = i64::try_from(value) else {
            return Err(PasswordProtectedKeyEnvelopeError::InvalidNamespace);
        };
        Self::try_from(value)
    }
}

impl Into<i128> for PasswordProtectedKeyEnvelopeNamespace {
    fn into(self) -> i128 {
        self.as_i64() as i128
    }
}

impl ContentNamespace for PasswordProtectedKeyEnvelopeNamespace {}

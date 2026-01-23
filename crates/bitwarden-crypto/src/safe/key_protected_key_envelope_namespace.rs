use crate::safe::KeyProtectedKeyEnvelopeError;

/// Key protected key envelopes are domain-separated within bitwarden, to prevent cross protocol attacks.
///
/// A new struct shall use a new key protected key envelope namespace. Generally, this means
/// that a key protected key envelope namespace has exactly one associated valid message struct. Internal
/// versioning within a namespace is permitted and up to the domain owner to ensure is done
/// correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyProtectedKeyEnvelopeNamespace {
    /// The namespace for device protected keys
    DeviceProtectedKey = 1,
    /// This namespace is only used in tests
    #[cfg(test)]
    ExampleNamespace = -1,
    /// This namespace is only used in tests
    #[cfg(test)]
    ExampleNamespace2 = -2,
}

impl KeyProtectedKeyEnvelopeNamespace {
    /// Returns the numeric value of the namespace.
    pub fn as_i64(&self) -> i64 {
        *self as i64
    }
}

impl TryFrom<i64> for KeyProtectedKeyEnvelopeNamespace {
    type Error = KeyProtectedKeyEnvelopeError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(KeyProtectedKeyEnvelopeNamespace::DeviceProtectedKey),
            #[cfg(test)]
            -1 => Ok(KeyProtectedKeyEnvelopeNamespace::ExampleNamespace),
            #[cfg(test)]
            -2 => Ok(KeyProtectedKeyEnvelopeNamespace::ExampleNamespace2),
            _ => Err(KeyProtectedKeyEnvelopeError::InvalidNamespace),
        }
    }
}

impl TryFrom<i128> for KeyProtectedKeyEnvelopeNamespace {
    type Error = KeyProtectedKeyEnvelopeError;

    fn try_from(value: i128) -> Result<Self, Self::Error> {
        let Ok(value) = i64::try_from(value) else {
            return Err(KeyProtectedKeyEnvelopeError::InvalidNamespace);
        };
        Self::try_from(value)
    }
}

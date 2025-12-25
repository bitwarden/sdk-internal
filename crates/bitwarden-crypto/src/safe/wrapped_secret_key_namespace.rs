use crate::safe::DataEnvelopeError;

/// Wrapped symmetric keys are separated by namespace. A namespace here describes a general function
/// of the key, such as "User Key". This prevents server-side swapping of keys which otherwise may
/// result in attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrappedSymmetricKeyNamespace {
    /// This namespace is only used in tests
    #[cfg(test)]
    ExampleNamespace = -1,
    /// This namespace is only used in tests
    #[cfg(test)]
    ExampleNamespace2 = -2,
}

impl WrappedSymmetricKeyNamespace {
    /// Returns the numeric value of the namespace.
    pub fn as_i64(&self) -> i64 {
        *self as i64
    }
}

struct InvalidNamespaceError;

impl TryFrom<i64> for WrappedSymmetricKeyNamespace {
    type Error = InvalidNamespaceError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            #[cfg(test)]
            -1 => Ok(WrappedSymmetricKeyNamespace::ExampleNamespace),
            #[cfg(test)]
            -2 => Ok(WrappedSymmetricKeyNamespace::ExampleNamespace2),
            _ => Err(InvalidNamespaceError),
        }
    }
}

impl TryFrom<i128> for WrappedSymmetricKeyNamespace {
    type Error = InvalidNamespaceError;

    fn try_from(value: i128) -> Result<Self, Self::Error> {
        let Ok(value) = i64::try_from(value) else {
            return Err(InvalidNamespaceError);
        };
        Self::try_from(value)
    }
}

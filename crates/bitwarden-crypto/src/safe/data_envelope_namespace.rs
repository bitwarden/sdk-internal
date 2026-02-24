use crate::{cose::ContentNamespace, safe::DataEnvelopeError};

/// Data envelopes are domain-separated within bitwarden, to prevent cross protocol attacks.
///
/// A new struct shall use a new data envelope namespace. Generally, this means
/// that a data envelope namespace has exactly one associated valid message struct. Internal
/// versioning within a namespace is permitted and up to the domain owner to ensure is done
/// correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataEnvelopeNamespace {
    /// The namespace for vault items ("ciphers")
    VaultItem = 1,
    /// This namespace is only used in tests
    #[cfg(test)]
    ExampleNamespace = -1,
    /// This namespace is only used in tests
    #[cfg(test)]
    ExampleNamespace2 = -2,
}

impl DataEnvelopeNamespace {
    /// Returns the numeric value of the namespace.
    pub fn as_i64(&self) -> i64 {
        *self as i64
    }
}

impl TryFrom<i128> for DataEnvelopeNamespace {
    type Error = DataEnvelopeError;

    fn try_from(value: i128) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(DataEnvelopeNamespace::VaultItem),
            #[cfg(test)]
            -1 => Ok(DataEnvelopeNamespace::ExampleNamespace),
            #[cfg(test)]
            -2 => Ok(DataEnvelopeNamespace::ExampleNamespace2),
            _ => Err(DataEnvelopeError::InvalidNamespace),
        }
    }
}

impl TryFrom<i64> for DataEnvelopeNamespace {
    type Error = DataEnvelopeError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        Self::try_from(i128::from(value))
    }
}

impl From<DataEnvelopeNamespace> for i128 {
    fn from(val: DataEnvelopeNamespace) -> Self {
        val.as_i64().into()
    }
}

impl ContentNamespace for DataEnvelopeNamespace {}

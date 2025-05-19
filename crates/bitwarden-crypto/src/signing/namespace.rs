use crate::CryptoError;

/// Signing is domain-separated within bitwarden, to prevent cross protocol attacks.
///
/// A new signed entity or protocol shall use a new signing namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningNamespace {
    #[allow(dead_code)]
    EncryptionMetadata = 1,
    #[allow(dead_code)]
    PublicKeyOwnershipClaim = 2,
    #[cfg(test)]
    Test = -1,
}

impl SigningNamespace {
    pub fn as_i64(&self) -> i64 {
        *self as i64
    }

    pub fn try_from_i64(value: i64) -> Result<Self, CryptoError> {
        match value {
            1 => Ok(Self::EncryptionMetadata),
            2 => Ok(Self::PublicKeyOwnershipClaim),
            #[cfg(test)]
            -1 => Ok(Self::Test),
            _ => Err(CryptoError::InvalidNamespace),
        }
    }
}

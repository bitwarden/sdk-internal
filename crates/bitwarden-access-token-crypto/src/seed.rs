//! The seed an [`crate::AccessTokenKey`] is derived from.

use std::fmt;

use bitwarden_crypto::generate_random_bytes;
use thiserror::Error;
use zeroize::Zeroizing;

const SEED_LEN: usize = 16;

/// The 16-byte secret an [`crate::AccessTokenKey`] is derived from. Never sent to a server; the
/// caller transports it to the token holder (e.g. inside a token string).
pub struct AccessTokenSeed(Zeroizing<[u8; SEED_LEN]>);

impl fmt::Debug for AccessTokenSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AccessTokenSeed")
            .field(&"[REDACTED]")
            .finish()
    }
}

/// Returned when a byte slice is the wrong length to be an [`AccessTokenSeed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("invalid access token seed length: expected {expected}, got {got}")]
pub struct AccessTokenSeedError {
    /// The length an access token seed must be.
    pub expected: usize,
    /// The length that was actually given.
    pub got: usize,
}

impl TryFrom<&[u8]> for AccessTokenSeed {
    type Error = AccessTokenSeedError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let array: [u8; SEED_LEN] = bytes.try_into().map_err(|_| AccessTokenSeedError {
            expected: SEED_LEN,
            got: bytes.len(),
        })?;
        Ok(Self(Zeroizing::new(array)))
    }
}

impl AccessTokenSeed {
    pub(crate) fn generate() -> Self {
        Self(generate_random_bytes())
    }

    /// The raw seed bytes.
    pub fn as_bytes(&self) -> &[u8; SEED_LEN] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_length_is_accepted() {
        let bytes = [0u8; SEED_LEN];
        assert!(AccessTokenSeed::try_from(bytes.as_slice()).is_ok());
    }

    #[test]
    fn wrong_length_is_rejected() {
        let bytes = [0u8; SEED_LEN - 1];
        let err = AccessTokenSeed::try_from(bytes.as_slice()).unwrap_err();
        assert_eq!(
            err,
            AccessTokenSeedError {
                expected: SEED_LEN,
                got: SEED_LEN - 1
            }
        );
    }
}

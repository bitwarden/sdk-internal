//! Cross-platform (WASM / UniFFI) bindings for random-number generation.

use bitwarden_error::bitwarden_error;
use rand::{Rng, RngExt};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::rng;

/// Error returned by [`SdkRandomNumberClient::gen_bytes`].
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum GenBytesError {
    /// More than 1 KiB of randomness was requested.
    #[error("gen_bytes() is limited to 1KiB; requested {requested} bytes")]
    TooManyBytes {
        /// The number of bytes that was requested.
        requested: u32,
    },
}

/// Error returned by [`SdkRandomNumberClient::gen_range`].
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum GenRangeError {
    /// `min` was greater than `max`, so the range is empty.
    #[error("Invalid range: min ({min}) must not exceed max ({max})")]
    InvalidRange {
        /// The requested lower bound.
        min: u32,
        /// The requested upper bound.
        max: u32,
    },
}

/// Client exposing random-number generation to cross-platform bindings.
#[derive(Default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct SdkRandomNumberClient;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[cfg_attr(feature = "uniffi", uniffi::export)]
impl SdkRandomNumberClient {
    /// Construct a new client.
    #[cfg_attr(feature = "wasm", wasm_bindgen(constructor))]
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new() -> Self {
        // UniFFI does not support associated (static) functions, so the client is exposed as an
        // object with a constructor and `&self` methods. The WASM binding mirrors that
        // shape (constructor + instance methods) so a single impl block serves both.
        SdkRandomNumberClient
    }

    /// Generate `len` cryptographically-secure random bytes.
    ///
    /// Returns [`GenBytesError::TooManyBytes`] if `len` exceeds 1 KiB. If you want over 1KiB of
    /// randomness, please reconsider your design.
    pub fn gen_bytes(&self, len: u32) -> Result<Vec<u8>, GenBytesError> {
        if len > 1024 {
            return Err(GenBytesError::TooManyBytes { requested: len });
        }

        let mut buf = vec![0u8; len as usize];
        rng().fill_bytes(&mut buf);
        Ok(buf)
    }

    /// Generate a random v4 UUID, sampled from a CRNG
    ///
    /// This has 122 random bits of entropy.
    pub fn gen_uuid(&self) -> String {
        let mut bytes = [0u8; 16];
        rng().fill_bytes(&mut bytes);
        uuid::Builder::from_random_bytes(bytes)
            .with_variant(uuid::Variant::RFC4122)
            .with_version(uuid::Version::Random)
            .into_uuid()
            .to_string()
    }

    /// Generate a cryptographically-secure random number in the range `[min, max]` (inclusive).
    ///
    /// Returns [`GenRangeError::InvalidRange`] if `min > max`.
    pub fn gen_range(&self, min: u32, max: u32) -> Result<u32, GenRangeError> {
        if min > max {
            return Err(GenRangeError::InvalidRange { min, max });
        }
        Ok(rng().random_range(min..=max))
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    #[test]
    fn gen_bytes_returns_requested_length() {
        let client = SdkRandomNumberClient::new();
        assert_eq!(client.gen_bytes(0).unwrap().len(), 0);
        assert_eq!(client.gen_bytes(1).unwrap().len(), 1);
        assert_eq!(client.gen_bytes(32).unwrap().len(), 32);
        // 1 KiB is the documented maximum and must succeed.
        assert_eq!(client.gen_bytes(1024).unwrap().len(), 1024);
    }

    #[test]
    fn gen_bytes_is_random() {
        let client = SdkRandomNumberClient::new();
        // Two independent draws differ with overwhelming probability.
        assert_ne!(client.gen_bytes(32).unwrap(), client.gen_bytes(32).unwrap());
    }

    #[test]
    fn gen_bytes_errors_above_1_kib() {
        let err = SdkRandomNumberClient::new().gen_bytes(1025).unwrap_err();
        assert!(matches!(
            err,
            GenBytesError::TooManyBytes { requested: 1025 }
        ));
    }

    #[test]
    fn gen_uuid_is_a_valid_random_v4_uuid() {
        let client = SdkRandomNumberClient::new();
        let uuid = Uuid::parse_str(&client.gen_uuid()).expect("a valid UUID string");
        assert_eq!(uuid.get_version(), Some(uuid::Version::Random));
        assert_eq!(uuid.get_variant(), uuid::Variant::RFC4122);
    }

    #[test]
    fn gen_uuid_is_distinct() {
        let client = SdkRandomNumberClient::new();
        assert_ne!(client.gen_uuid(), client.gen_uuid());
    }

    #[test]
    fn gen_range_stays_within_inclusive_bounds() {
        let client = SdkRandomNumberClient::new();
        for _ in 0..1000 {
            let n = client.gen_range(10, 20).unwrap();
            assert!((10..=20).contains(&n));
        }
    }

    #[test]
    fn gen_range_with_single_value_is_that_value() {
        let client = SdkRandomNumberClient::new();
        assert_eq!(client.gen_range(7, 7).unwrap(), 7);
    }

    #[test]
    fn gen_range_errors_when_min_exceeds_max() {
        let err = SdkRandomNumberClient::new().gen_range(20, 10).unwrap_err();
        assert!(matches!(
            err,
            GenRangeError::InvalidRange { min: 20, max: 10 }
        ));
    }
}

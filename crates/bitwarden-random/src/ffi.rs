//! Cross-platform (WASM / UniFFI) bindings for random-number generation.

use rand::{Rng, RngExt};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::rng;

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
    /// WARNING: This panics over 1KiB. If you want over 1KiB of randomness, please reconsider.
    pub fn gen_bytes(&self, len: u32) -> Vec<u8> {
        if len > 1024 {
            panic!(
                "gen_bytes() is limited to 1KiB; please reconsider your design if you need more randomness"
            );
        }

        let mut buf = vec![0u8; len as usize];
        rng().fill_bytes(&mut buf);
        buf
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
    /// WARNING: Panics if `min > max`.
    pub fn gen_range(&self, min: u32, max: u32) -> u32 {
        rng().random_range(min..=max)
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    #[test]
    fn gen_bytes_returns_requested_length() {
        let client = SdkRandomNumberClient::new();
        assert_eq!(client.gen_bytes(0).len(), 0);
        assert_eq!(client.gen_bytes(1).len(), 1);
        assert_eq!(client.gen_bytes(32).len(), 32);
        // 1 KiB is the documented maximum and must not panic.
        assert_eq!(client.gen_bytes(1024).len(), 1024);
    }

    #[test]
    fn gen_bytes_is_random() {
        let client = SdkRandomNumberClient::new();
        // Two independent draws differ with overwhelming probability.
        assert_ne!(client.gen_bytes(32), client.gen_bytes(32));
    }

    #[test]
    #[should_panic(expected = "1KiB")]
    fn gen_bytes_panics_above_1_kib() {
        SdkRandomNumberClient::new().gen_bytes(1025);
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
            let n = client.gen_range(10, 20);
            assert!((10..=20).contains(&n));
        }
    }

    #[test]
    fn gen_range_with_single_value_is_that_value() {
        let client = SdkRandomNumberClient::new();
        assert_eq!(client.gen_range(7, 7), 7);
    }

    #[test]
    #[should_panic]
    fn gen_range_panics_when_min_exceeds_max() {
        SdkRandomNumberClient::new().gen_range(20, 10);
    }
}

//! WASM integration tests for the [`SdkRandomNumberClient`] FFI, exercising the bindings as
//! compiled for the `wasm32` target (including the `getrandom` `wasm_js` backend).
//!
//! Run with:
//! `cargo test --target wasm32-unknown-unknown --features wasm -p bitwarden-random`
#![cfg(all(target_arch = "wasm32", feature = "wasm"))]

use bitwarden_random::SdkRandomNumberClient;
use uuid::Uuid;
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn gen_bytes_returns_requested_length() {
    let client = SdkRandomNumberClient::new();
    assert_eq!(client.gen_bytes(0).unwrap().len(), 0);
    assert_eq!(client.gen_bytes(32).unwrap().len(), 32);
    // 1 KiB is the documented maximum and must succeed.
    assert_eq!(client.gen_bytes(1024).unwrap().len(), 1024);
}

#[wasm_bindgen_test]
fn gen_bytes_errors_above_1_kib() {
    // Over the 1 KiB limit returns an error instead of trapping.
    assert!(SdkRandomNumberClient::new().gen_bytes(1025).is_err());
}

#[wasm_bindgen_test]
fn gen_bytes_is_random() {
    let client = SdkRandomNumberClient::new();
    assert_ne!(client.gen_bytes(32).unwrap(), client.gen_bytes(32).unwrap());
}

#[wasm_bindgen_test]
fn gen_uuid_is_a_valid_random_v4_uuid() {
    let client = SdkRandomNumberClient::new();
    let uuid = Uuid::parse_str(&client.gen_uuid()).expect("a valid UUID string");
    assert_eq!(uuid.get_version(), Some(uuid::Version::Random));
    assert_eq!(uuid.get_variant(), uuid::Variant::RFC4122);
}

#[wasm_bindgen_test]
fn gen_uuid_is_distinct() {
    let client = SdkRandomNumberClient::new();
    assert_ne!(client.gen_uuid(), client.gen_uuid());
}

#[wasm_bindgen_test]
fn gen_range_stays_within_inclusive_bounds() {
    let client = SdkRandomNumberClient::new();
    for _ in 0..1000 {
        let n = client.gen_range(10, 20).unwrap();
        assert!((10..=20).contains(&n));
    }
    assert_eq!(client.gen_range(7, 7).unwrap(), 7);
    // An inverted range returns an error instead of trapping.
    assert!(client.gen_range(20, 10).is_err());
}

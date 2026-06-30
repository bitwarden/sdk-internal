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
    assert_eq!(client.gen_bytes(0).len(), 0);
    assert_eq!(client.gen_bytes(32).len(), 32);
    // 1 KiB is the documented maximum and must not panic.
    assert_eq!(client.gen_bytes(1024).len(), 1024);
}

#[wasm_bindgen_test]
fn gen_bytes_is_random() {
    let client = SdkRandomNumberClient::new();
    assert_ne!(client.gen_bytes(32), client.gen_bytes(32));
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
        let n = client.gen_range(10, 20);
        assert!((10..=20).contains(&n));
    }
    assert_eq!(client.gen_range(7, 7), 7);
}

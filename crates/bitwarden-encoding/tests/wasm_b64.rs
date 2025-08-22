//! Test for Base64 encoding and decoding in WASM
#![cfg(all(target_arch = "wasm32", feature = "wasm"))]

use bitwarden_encoding::B64;
use wasm_bindgen_test::*;

#[cfg(feature = "wasm")]
#[wasm_bindgen_test]
fn test_b64_wasm_serde_serialize() {
    let data = b"WASM serialization test";
    let b64 = B64::from(data.as_slice());

    let js_value = serde_wasm_bindgen::to_value(&b64).unwrap();

    // The B64 should serialize as a base64 string
    let expected_b64_string = "V0FTTSBzZXJpYWxpemF0aW9uIHRlc3Q=";
    assert_eq!(js_value.as_string().unwrap(), expected_b64_string);
}

#[cfg(feature = "wasm")]
#[wasm_bindgen_test]
fn test_b64_wasm_serde_deserialize() {
    use wasm_bindgen::JsValue;

    let base64_string = "V0FTTSBzZXJpYWxpemF0aW9uIHRlc3Q=";
    let js_value = JsValue::from_str(base64_string);

    let b64: B64 = serde_wasm_bindgen::from_value(js_value).unwrap();
    assert_eq!(b64.as_ref(), b"WASM serialization test");
}

#[cfg(feature = "wasm")]
#[wasm_bindgen_test]
fn test_b64_wasm_serde_round_trip() {
    let original_data = "Round trip WASM test with Unicode: 🦀🚀".as_bytes();
    let original_b64 = B64::from(original_data);

    // Serialize to JS value
    let js_value = serde_wasm_bindgen::to_value(&original_b64).unwrap();

    // Deserialize back to B64
    let deserialized_b64: B64 = serde_wasm_bindgen::from_value(js_value).unwrap();

    assert_eq!(original_b64.as_ref(), deserialized_b64.as_ref());
    assert_eq!(deserialized_b64.as_ref(), original_data);
}

#![allow(missing_docs)]

#[cfg(feature = "wasm")]
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
#[cfg(feature = "wasm")]
#[allow(dead_code)] // Not actually dead, but rust-analyzer doesn't understand `wasm_bindgen_test`
fn converts_to_js_error_using_to_string() {
    use std::fmt::Display;

    use bitwarden_error::{bitwarden_error, wasm::SdkJsError};
    use wasm_bindgen::JsValue;

    #[bitwarden_error(basic)]
    struct SomeError;
    impl Display for SomeError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "This is an error")
        }
    }

    let simple = SomeError;
    let js_value: JsValue = simple.into();

    let js_error = SdkJsError::from(js_value);
    assert_eq!(js_error.name(), "SomeError");
    assert_eq!(js_error.message(), "This is an error");
}

#[wasm_bindgen_test]
#[cfg(feature = "wasm")]
#[allow(dead_code)] // Not actually dead, but rust-analyzer doesn't understand `wasm_bindgen_test`
fn outputs_different_name_when_given_export_as() {
    use std::fmt::Display;

    use bitwarden_error::{bitwarden_error, wasm::SdkJsError};
    use wasm_bindgen::JsValue;

    #[bitwarden_error(basic, export_as = "SomeOtherError")]
    struct SomeError;
    impl Display for SomeError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "This is an error")
        }
    }

    let simple = SomeError;
    let js_value: JsValue = simple.into();

    let js_error = SdkJsError::from(js_value);
    assert_eq!(js_error.name(), "SomeOtherError");
    assert_eq!(js_error.message(), "This is an error");
}

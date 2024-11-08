use bitwarden_error::prelude::*;
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
#[cfg(feature = "wasm")]
fn converts_to_js_error_using_to_string() {
    #[derive(Debug, BasicError)]
    struct SomeError;
    impl ToString for SomeError {
        fn to_string(&self) -> String {
            "This is an error".to_string()
        }
    }

    let simple = SomeError;
    let js_value: JsValue = simple.into();

    let js_error = JsError::from(js_value);
    assert_eq!(js_error.name(), "SomeError");
    assert_eq!(js_error.message(), "This is an error");
}

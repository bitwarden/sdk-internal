#![allow(missing_docs)]

#[cfg(feature = "wasm")]
use wasm_bindgen_test::*;

#[allow(dead_code)]
// Not actually dead, but rust-analyzer doesn't understand `wasm_bindgen_test`
#[wasm_bindgen_test]
#[cfg(feature = "wasm")]
// `full` errors are just forwarded to TSify and Serde so this is just a smoke test
fn converts_to_js() {
    use bitwarden_error::bitwarden_error;
    use wasm_bindgen::JsValue;

    #[bitwarden_error(full)]
    enum SomeError {
        Foo(String),
        Bar(String),
        Baz(String),
    }

    let simple = SomeError::Baz("This is an error".to_string());
    let js_value: JsValue = simple.into();

    // Errors only natively support rust -> js and so we use Reflect to get the value straight from
    // the JSValue
    let value = js_sys::Reflect::get(&js_value, &JsValue::from("Baz")).unwrap_or(JsValue::NULL);
    assert_eq!(value.as_string().unwrap_or_default(), "This is an error");
}

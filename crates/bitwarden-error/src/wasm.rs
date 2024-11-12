use wasm_bindgen::prelude::*;

#[cfg_attr(feature = "wasm", wasm_bindgen(typescript_custom_section))]
const TS_APPEND_CONTENT: &'static str = r#"
    export type SdkError<T> = Error & { sdkError: T };
"#;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
extern "C" {
    #[wasm_bindgen(js_name = Error)]
    pub type SdkJsError;

    #[wasm_bindgen(constructor, js_class = Error)]
    pub fn new(message: String) -> SdkJsError;

    #[wasm_bindgen(method, getter, structural)]
    pub fn message(this: &SdkJsError) -> String;

    #[wasm_bindgen(method, getter, structural)]
    pub fn name(this: &SdkJsError) -> String;

    #[wasm_bindgen(method, setter, structural)]
    pub fn set_variant(this: &SdkJsError, name: String);

    #[wasm_bindgen(method, getter, structural)]
    pub fn variant(this: &SdkJsError) -> String;

    #[wasm_bindgen(method, setter, structural)]
    pub fn set_name(this: &SdkJsError, name: String);

    #[wasm_bindgen(method, getter, structural, js_name = sdkError)]
    pub fn sdk_error(this: &SdkJsError) -> String;

    #[wasm_bindgen(method, setter, structural)]
    pub fn set_sdk_error(this: &SdkJsError, sdkError: JsValue);
}

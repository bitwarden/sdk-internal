use wasm_bindgen::prelude::*;

#[allow(missing_docs)]
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
    pub fn set_name(this: &SdkJsError, name: String);

    #[wasm_bindgen(method, getter, structural)]
    pub fn variant(this: &SdkJsError) -> String;

    #[wasm_bindgen(method, setter, structural)]
    pub fn set_variant(this: &SdkJsError, variant: String);
}

use wasm_bindgen::prelude::*;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
extern "C" {
    #[wasm_bindgen(js_name = Error)]
    pub type JsError;

    #[wasm_bindgen(constructor, js_class = Error)]
    pub fn new(message: String) -> JsError;

    #[wasm_bindgen(method, getter, structural)]
    pub fn message(this: &JsError) -> String;

    #[wasm_bindgen(method, getter, structural)]
    pub fn name(this: &JsError) -> String;

    #[wasm_bindgen(method, setter, structural)]
    pub fn set_name(this: &JsError, name: String);

    #[wasm_bindgen(method, getter, structural)]
    pub fn variant(this: &JsError) -> String;

    #[wasm_bindgen(method, setter, structural)]
    pub fn set_variant(this: &JsError, variant: String);
}

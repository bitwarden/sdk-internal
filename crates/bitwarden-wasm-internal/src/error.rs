use wasm_bindgen::prelude::*;

// Importing an error class defined in JavaScript instead of defining it in Rust
// allows us to extend the `Error` class. It also provides much better console output.
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = Error)]
    type JsError;

    #[wasm_bindgen(constructor, js_class = Error)]
    fn new(message: String) -> JsError;

    #[wasm_bindgen(method, getter, structural)]
    fn name(this: &JsError) -> String;

    #[wasm_bindgen(method, setter, structural)]
    fn set_name(this: &JsError, name: String);

    #[wasm_bindgen(method, getter, structural)]
    fn variant(this: &JsError) -> String;

    #[wasm_bindgen(method, setter, structural)]
    fn set_variant(this: &JsError, variant: String);
}

pub type Result<T, E = GenericError> = std::result::Result<T, E>;

pub struct GenericError(pub String);

impl<T: ToString> From<T> for GenericError {
    fn from(error: T) -> Self {
        GenericError(error.to_string())
    }
}

impl From<GenericError> for JsValue {
    fn from(error: GenericError) -> Self {
        JsError::new(error.0).into()
    }
}

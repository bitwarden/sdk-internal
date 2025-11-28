use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct FieldValue {
    pub(crate) name: String,
    pub(crate) value: String,
}

#[wasm_bindgen]
impl FieldValue {
    #[wasm_bindgen(constructor)]
    pub fn new(name: String, value: String) -> Self {
        Self { name, value }
    }
}

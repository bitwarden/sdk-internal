use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct FieldValue {
    #[wasm_bindgen(getter_with_clone)]
    pub name: String,
    #[wasm_bindgen(getter_with_clone)]
    pub value: String,
}

#[wasm_bindgen]
impl FieldValue {
    #[wasm_bindgen(constructor)]
    pub fn new(name: String, value: String) -> Self {
        Self { name, value }
    }
}

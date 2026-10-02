use bitwarden_ffi::wasm_export;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Canvas;

#[wasm_export]
#[wasm_bindgen(js_class = Canvas)]
impl Canvas {
    pub fn draw(&self) {}
}

fn main() {}

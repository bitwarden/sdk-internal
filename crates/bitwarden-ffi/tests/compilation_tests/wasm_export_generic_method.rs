use bitwarden_ffi::wasm_export;

pub struct Canvas;

#[wasm_export]
impl Canvas {
    pub fn draw<T: Copy>(&self, shape: T) -> T {
        shape
    }
}

fn main() {}

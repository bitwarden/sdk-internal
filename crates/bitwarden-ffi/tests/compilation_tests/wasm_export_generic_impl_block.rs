use bitwarden_ffi::wasm_export;

pub struct Canvas<T>(T);

#[wasm_export]
impl<T> Canvas<T> {
    pub fn get(&self) -> &T {
        &self.0
    }
}

fn main() {}

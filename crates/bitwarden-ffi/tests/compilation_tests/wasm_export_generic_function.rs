use bitwarden_ffi::wasm_export;

#[wasm_export]
pub fn identity<T>(value: T) -> T {
    value
}

fn main() {}

use bitwarden_ffi::wasm_record;

#[wasm_record]
pub struct Wrapper<T> {
    pub inner: T,
}

fn main() {}

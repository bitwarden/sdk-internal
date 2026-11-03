use bitwarden_ffi::wasm_record;

#[wasm_record(into_wasm_abi)]
pub struct Point {
    pub x: i32,
}

fn main() {}

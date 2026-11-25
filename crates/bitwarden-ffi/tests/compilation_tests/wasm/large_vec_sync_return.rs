use bitwarden_ffi::{LargeVec, wasm_export, wasm_record};
use serde::{Deserialize, Serialize};

#[wasm_record]
#[derive(Serialize, Deserialize)]
pub struct Item {
    pub value: u32,
}

#[wasm_export]
pub fn echo(items: LargeVec<Item>) -> LargeVec<Item> {
    items
}

fn main() {}

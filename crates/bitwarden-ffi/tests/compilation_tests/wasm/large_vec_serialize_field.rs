use bitwarden_ffi::{LargeVec, wasm_record};
use serde::{Deserialize, Serialize};

#[wasm_record]
#[derive(Serialize, Deserialize)]
pub struct Item {
    pub value: u32,
}

#[derive(Serialize)]
pub struct Items {
    pub items: LargeVec<Item>,
}

fn main() {}

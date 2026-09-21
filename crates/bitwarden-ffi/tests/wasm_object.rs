#![allow(missing_docs)]

use bitwarden_ffi::{wasm_export, wasm_object};

// --- Test: a handle type stays usable from Rust ---

#[wasm_object]
pub struct Counter {
    count: u32,
}

#[wasm_export]
impl Counter {
    pub fn start() -> Counter {
        Counter { count: 0 }
    }

    pub fn increment(&mut self) {
        self.count += 1;
    }

    pub fn count(&self) -> u32 {
        self.count
    }
}

#[test]
fn a_handle_type_stays_usable_from_rust() {
    let mut counter = Counter::start();
    counter.increment();

    assert_eq!(counter.count(), 1);
}

// --- Test: arguments reach wasm_bindgen ---

#[wasm_object(js_name = Renamed, skip_typescript)]
pub struct RenamedHandle {
    pub value: u32,
}

#[test]
fn a_renamed_handle_keeps_its_rust_name() {
    assert_eq!(RenamedHandle { value: 3 }.value, 3);
}

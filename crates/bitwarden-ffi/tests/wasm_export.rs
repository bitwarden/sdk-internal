#![allow(missing_docs)]

use bitwarden_ffi::{wasm_export, wasm_object};

// --- Test: renames wasm_only method ---

#[wasm_object]
pub struct RenameTarget;

#[wasm_export]
impl RenameTarget {
    #[wasm_only]
    pub fn bar() {}
}

#[test]
#[allow(deprecated)]
fn renames_wasm_only_method() {
    RenameTarget::__wasm_only_bar();
}

// --- Test: custom note is accepted ---

#[wasm_object]
pub struct CustomNoteTarget;

#[wasm_export]
impl CustomNoteTarget {
    #[wasm_only(note = "Use the native API instead.")]
    pub fn with_custom_note() {}
}

#[test]
#[allow(deprecated)]
fn custom_note_is_accepted() {
    CustomNoteTarget::__wasm_only_with_custom_note();
}

// --- Test: leaves unmarked methods unchanged ---

#[wasm_object(js_name = Unmarked)]
pub struct UnmarkedTarget;

#[wasm_export(js_class = Unmarked)]
impl UnmarkedTarget {
    pub fn untouched() -> i32 {
        42
    }

    #[cfg_attr(feature = "wasm", wasm_bindgen(js_name = alreadyNamed))]
    pub fn already_named() -> i32 {
        7
    }
}

#[test]
fn leaves_unmarked_methods_unchanged() {
    assert_eq!(UnmarkedTarget::untouched(), 42);
    assert_eq!(UnmarkedTarget::already_named(), 7);
}

// --- Test: exports a free function ---

#[wasm_export(js_name = freeFunction)]
pub fn free_function(value: i32) -> i32 {
    value
}

#[test]
fn exports_a_free_function() {
    assert_eq!(free_function(1), 1);
}

#![allow(missing_docs)]

use bitwarden_ffi::wasm_export;
use wasm_bindgen::prelude::*;

// --- Test: renames wasm_only method ---

#[wasm_bindgen]
pub struct RenameTarget;

#[wasm_export]
#[wasm_bindgen]
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

#[wasm_bindgen]
pub struct CustomNoteTarget;

#[wasm_export]
#[wasm_bindgen]
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

#[wasm_bindgen]
pub struct UnmarkedTarget;

#[wasm_export]
#[wasm_bindgen]
impl UnmarkedTarget {
    pub fn untouched() -> i32 {
        42
    }
}

#[test]
fn leaves_unmarked_methods_unchanged() {
    assert_eq!(UnmarkedTarget::untouched(), 42);
}

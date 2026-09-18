//! Utilities for FFI bindings (WASM, UniFFI).
//!
//! Re-exports proc macros from `bitwarden-ffi-macro`.

pub use bitwarden_ffi_macro::{wasm_export, wasm_object, wasm_record};

/// What the macro expansions name, so a call site imports nothing and names only this crate.
///
/// Not a public API.
#[cfg(feature = "wasm")]
#[doc(hidden)]
pub mod _macro {
    pub use tsify::Tsify;
    pub use wasm_bindgen::prelude::wasm_bindgen;
}

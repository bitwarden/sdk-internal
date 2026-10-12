//! Utilities for FFI bindings (WASM, UniFFI).
//!
//! Re-exports proc macros from `bitwarden-ffi-macro`, plus the wire traits. [`FromWasm`] and
//! [`ToWasm`] explain how a type crosses the wasm ABI.

#[cfg(feature = "wasm")]
mod wire;
mod wire_macros;

pub use bitwarden_ffi_macro::{wasm_export, wasm_object, wasm_record};
#[cfg(feature = "wasm")]
pub use wire::{FromWasm, ToWasm, WireError};
#[cfg(feature = "wasm")]
#[doc(hidden)]
pub use wire::{format_wire_string, parse_wire_string};

/// What the macro expansions name, so a call site imports nothing and names only this crate.
///
/// Not a public API.
#[cfg(feature = "wasm")]
#[doc(hidden)]
pub mod _macro {
    pub use tsify::Tsify;
    pub use ::wasm_bindgen;
    pub use ::wasm_bindgen::prelude::wasm_bindgen;
}

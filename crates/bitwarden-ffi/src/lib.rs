//! Utilities for FFI bindings (WASM, UniFFI).
//!
//! Re-exports the proc macros from `bitwarden-ffi-macro`, plus the types the code they generate
//! refers to.

#[cfg(feature = "wasm")]
mod wire;

#[cfg(feature = "wasm")]
pub use bitwarden_error::wasm::CONVERSION_ERROR_NAME;
pub use bitwarden_ffi_macro::{wasm_export, wasm_object, wasm_record};
#[cfg(feature = "wasm")]
pub use tsify::{Error as TsifyError, Ts};
#[cfg(feature = "wasm")]
pub use wire::{FromWasm, Never, ToWasm, TsError};

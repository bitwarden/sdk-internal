#![doc = include_str!("../README.md")]

#[allow(missing_docs)]
pub mod flat_error;

#[cfg(feature = "wasm")]
#[allow(missing_docs)]
pub mod wasm;

/// Re-export the `js_sys` crate since the proc macro depends on it.
#[cfg(feature = "wasm")]
#[doc(hidden)]
pub use ::js_sys;
/// Re-export the `tsify_next` crate since the proc macro depends on it.
#[cfg(feature = "wasm")]
#[doc(hidden)]
pub use ::tsify_next;
/// Re-export the `wasm_bindgen` crate since the proc macro depends on it.
#[cfg(feature = "wasm")]
#[doc(hidden)]
pub use ::wasm_bindgen;
pub use bitwarden_error_macro::bitwarden_error;

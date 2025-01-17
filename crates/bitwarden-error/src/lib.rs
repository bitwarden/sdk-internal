pub mod flat_error;

#[cfg(feature = "wasm")]
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
use documented::docs_const;

pub mod prelude {
    pub use bitwarden_error_macro::*;

    pub use crate::flat_error::FlatError;
    #[cfg(feature = "wasm")]
    pub use crate::wasm::SdkJsError;
}

/// A test function.
#[docs_const]
pub fn test() {
    println!("Hello, world!");
}

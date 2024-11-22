pub mod flat_error;

#[cfg(feature = "wasm")]
pub mod wasm;

/// Re-export the `js_sys` crate since the proc macro depends on it.
#[cfg(feature = "wasm")]
pub use ::js_sys;

pub mod prelude {
    pub use bitwarden_error_macro::*;

    pub use crate::flat_error::FlatError;
    #[cfg(feature = "wasm")]
    pub use crate::wasm::SdkJsError;
}

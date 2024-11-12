pub mod flat_error;

#[cfg(feature = "wasm")]
pub mod wasm;

pub mod prelude {
    pub use bitwarden_error_macro::*;

    pub use crate::flat_error::FlatError;
    #[cfg(feature = "wasm")]
    pub use crate::wasm::SdkJsError;
}

pub mod flat_error;

pub mod prelude {
    pub use crate::flat_error::FlatError;
    pub use crate::BitwardenError;
    pub use bitwarden_error_macro::*;

    #[cfg(feature = "wasm")]
    pub use wasm_bindgen::prelude::*;
}

pub trait BitwardenError: flat_error::FlatError + ToString {}

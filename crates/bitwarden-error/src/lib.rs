pub mod variant;

pub mod prelude {
    pub use crate::variant::ErrorVariant;
    pub use crate::BitwardenError;
    pub use bitwarden_error_macro::*;
}

pub trait BitwardenError: variant::ErrorVariant + ToString {}

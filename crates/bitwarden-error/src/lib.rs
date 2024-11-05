pub mod metadata;

pub mod prelude {
    pub use crate::metadata::{AsErrorMetadata, ErrorMetadata};
    pub use bitwarden_error_macro::AsErrorMetadata;
}

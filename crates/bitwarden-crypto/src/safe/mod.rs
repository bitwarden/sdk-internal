#![doc = include_str!("./README.md")]

mod password_protected_key_envelope;
pub use password_protected_key_envelope::*;
mod password_protected_key_envelope_namespace;
pub use password_protected_key_envelope_namespace::*;
mod cose_envelope_helpers;
mod symmetric_key_envelope;
pub use symmetric_key_envelope::SymmetrickeyEnvelope;
mod data_envelope;
pub use data_envelope::*;
mod data_envelope_namespace;
pub use data_envelope_namespace::DataEnvelopeNamespace;

use crate::cose::{
    ContentNamespace, SAFE_CONTENT_NAMESPACE, SAFE_OBJECT_NAMESPACE, SafeObjectNamespace,
    extract_integer,
};

enum ExtractionError {
    MissingNamespace,
    InvalidNamespace,
}

fn extract_safe_object_namespace(
    header: &coset::Header,
) -> Result<SafeObjectNamespace, ExtractionError> {
    match extract_integer(header, SAFE_OBJECT_NAMESPACE, "safe object namespace") {
        Ok(value) => value
            .try_into()
            .map_err(|_| ExtractionError::InvalidNamespace),
        Err(_) => Err(ExtractionError::MissingNamespace),
    }
}

fn extract_safe_content_namespace<T: ContentNamespace>(
    header: &coset::Header,
) -> Result<T, ExtractionError> {
    match extract_integer(header, SAFE_CONTENT_NAMESPACE, "safe content namespace") {
        Ok(value) => value
            .try_into()
            .map_err(|_| ExtractionError::InvalidNamespace),
        Err(_) => Err(ExtractionError::MissingNamespace),
    }
}

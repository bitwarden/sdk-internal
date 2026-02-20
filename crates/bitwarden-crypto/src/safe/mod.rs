#![doc = include_str!("./README.md")]

mod password_protected_key_envelope;
pub use password_protected_key_envelope::*;
mod password_protected_key_envelope_namespace;
pub use password_protected_key_envelope_namespace::*;
mod data_envelope;
pub use data_envelope::*;
mod data_envelope_namespace;
pub use data_envelope_namespace::DataEnvelopeNamespace;

use crate::cose::{
    ContentNamespace, SAFE_CONTENT_NAMESPACE, SAFE_OBJECT_NAMESPACE, SafeObjectNamespace,
    extract_integer,
};

fn extract_safe_object_namespace(
    header: &coset::Header,
) -> Result<SafeObjectNamespace, DataEnvelopeError> {
    match extract_integer(header, SAFE_OBJECT_NAMESPACE, "safe object namespace") {
        Ok(value) => value.try_into().map_err(|_| {
            DataEnvelopeError::ParsingError("Invalid safe object namespace".to_string())
        }),
        Err(_) => Err(DataEnvelopeError::ParsingError(
            "Missing object namespace".to_string(),
        )),
    }
}

fn extract_safe_content_namespace<T: ContentNamespace>(
    header: &coset::Header,
) -> Result<T, DataEnvelopeError> {
    match extract_integer(header, SAFE_CONTENT_NAMESPACE, "safe content namespace") {
        Ok(value) => value.try_into().map_err(|_| {
            DataEnvelopeError::ParsingError("Invalid safe content namespace".to_string())
        }),
        Err(_) => Err(DataEnvelopeError::ParsingError(
            "Missing content namespace".to_string(),
        )),
    }
}

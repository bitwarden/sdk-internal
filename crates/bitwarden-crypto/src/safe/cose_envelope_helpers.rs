//! Shared helpers for COSE-encrypted key envelopes.

use crate::{
    cose::{
        CONTAINED_KEY_ID, SAFE_CONTENT_NAMESPACE, SAFE_OBJECT_NAMESPACE, extract_bytes,
        extract_integer,
    },
    keys::{KEY_ID_SIZE, KeyId},
};

pub(super) enum ExtractionError {
    MissingField,
    InvalidField,
}

/// Extract the content namespace from a COSE header.
pub(super) fn extract_content_namespace(header: &coset::Header) -> Result<i64, ExtractionError> {
    match extract_integer(header, SAFE_CONTENT_NAMESPACE, "content namespace") {
        Ok(value) => value.try_into().map_err(|_| ExtractionError::InvalidField),
        Err(_) => Err(ExtractionError::MissingField),
    }
}

/// Extract the safe object namespace from a COSE header.
pub(super) fn extract_object_namespace(header: &coset::Header) -> Result<i64, ExtractionError> {
    match extract_integer(header, SAFE_OBJECT_NAMESPACE, "safe object namespace") {
        Ok(value) => value.try_into().map_err(|_| ExtractionError::InvalidField),
        Err(_) => Err(ExtractionError::MissingField),
    }
}

/// Extract the contained key ID from a COSE header, if present.
pub(super) fn extract_contained_key_id(
    header: &coset::Header,
) -> Result<Option<KeyId>, ExtractionError> {
    let key_id_bytes = extract_bytes(header, CONTAINED_KEY_ID, "key id");

    if let Ok(bytes) = key_id_bytes {
        let key_id_array: [u8; KEY_ID_SIZE] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| ExtractionError::InvalidField)?;
        Ok(Some(KeyId::from(key_id_array)))
    } else {
        Ok(None)
    }
}

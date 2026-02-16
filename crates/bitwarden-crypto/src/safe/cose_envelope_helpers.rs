//! Shared helpers for COSE-encrypted key envelopes.

use thiserror::Error;
use crate::{
    cose::{
        CONTAINED_KEY_ID, CONTENT_NAMESPACE, SAFE_OBJECT_NAMESPACE, extract_bytes, extract_integer,
    },
    keys::{KEY_ID_SIZE, KeyId},
};

/// Errors that can occur when sealing or unsealing a key with envelope operations.
#[derive(Debug, Error)]
pub enum KeyProtectedKeyEnvelopeError {
    /// The wrapping key provided is incorrect or the envelope was tampered with
    #[error("Wrong key")]
    WrongKey,
    /// The envelope could not be parsed correctly
    #[error("Parsing error {0}")]
    Parsing(String),
    /// There is no key for the provided key id in the key store
    #[error("Key missing error")]
    KeyMissing,
    /// The key store could not be written to, for example due to being read-only
    #[error("Could not write to key store")]
    KeyStore,
    /// The wrong unseal method was used for the key type
    #[error("Wrong key type")]
    WrongKeyType,
    /// The key protected key envelope namespace is invalid.
    #[error("Invalid namespace")]
    InvalidNamespace,
}

/// Extract the content namespace from a COSE header.
pub(super) fn extract_envelope_namespace(
    header: &coset::Header,
) -> Result<i64, KeyProtectedKeyEnvelopeError> {
    header
        .rest
        .iter()
        .find_map(|(label, value)| match (label, value) {
            (coset::Label::Int(key), ciborium::Value::Integer(int))
                if *key == CONTENT_NAMESPACE =>
            {
                let decoded: i128 = (*int).into();
                decoded.try_into().ok()
            }
            _ => None,
        })
        .ok_or(KeyProtectedKeyEnvelopeError::InvalidNamespace)
}

/// Extract the safe object namespace from a COSE header.
pub(super) fn extract_safe_object_namespace(
    header: &coset::Header,
) -> Result<i64, KeyProtectedKeyEnvelopeError> {
    match extract_integer(header, SAFE_OBJECT_NAMESPACE, "safe object namespace") {
        Ok(value) => value.try_into().map_err(|_| {
            KeyProtectedKeyEnvelopeError::Parsing("Invalid safe object namespace".to_string())
        }),
        Err(_) => Err(KeyProtectedKeyEnvelopeError::Parsing(
            "Missing object namespace".to_string(),
        )),
    }
}

/// Extract the contained key ID from a COSE header, if present.
pub(super) fn extract_contained_key_id(
    header: &coset::Header,
) -> Result<Option<KeyId>, KeyProtectedKeyEnvelopeError> {
    let key_id_bytes = extract_bytes(header, CONTAINED_KEY_ID, "key id");

    if let Ok(bytes) = key_id_bytes {
        let key_id_array: [u8; KEY_ID_SIZE] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| KeyProtectedKeyEnvelopeError::Parsing("Invalid key id".to_string()))?;
        Ok(Some(KeyId::from(key_id_array)))
    } else {
        Ok(None)
    }
}

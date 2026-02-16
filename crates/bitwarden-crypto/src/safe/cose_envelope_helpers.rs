//! Shared helpers for COSE-encrypted key envelopes.

use ciborium::{Value, value::Integer};
use coset::HeaderBuilder;
use thiserror::Error;

use crate::{
    ContentFormat, CryptoError, SymmetricCryptoKey,
    cose::{
        CONTAINED_KEY_ID, KEY_PROTECTED_KEY_ENVELOPE_NAMESPACE, KEY_PROTECTED_KEY_TYPE,
        extract_bytes,
    },
    keys::{KEY_ID_SIZE, KeyId},
    xchacha20::{self},
};

use super::KeyProtectedKeyEnvelopeNamespace;

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

pub(super) fn seal_cose_key(
    key_to_seal_bytes: &[u8],
    content_format: ContentFormat,
    wrapping_key: &SymmetricCryptoKey,
    namespace: KeyProtectedKeyEnvelopeNamespace,
    contained_key_id: Option<KeyId>,
) -> Result<coset::CoseEncrypt0, KeyProtectedKeyEnvelopeError> {
    // Extract the XChaCha20Poly1305 key from the wrapping key
    let wrapping_key_inner = match wrapping_key {
        SymmetricCryptoKey::XChaCha20Poly1305Key(key) => key,
        _ => {
            return Err(KeyProtectedKeyEnvelopeError::Parsing(
                "Wrapping key must be XChaCha20Poly1305".to_string(),
            ));
        }
    };
    let mut nonce = [0u8; xchacha20::NONCE_SIZE];

    let mut protected_header = HeaderBuilder::from(content_format)
        .value(
            KEY_PROTECTED_KEY_TYPE,
            Value::Integer(Integer::from(envelope_type_label)),
        )
        .value(
            KEY_PROTECTED_KEY_ENVELOPE_NAMESPACE,
            Value::Integer(Integer::from(namespace.as_i64())),
        );

    if let Some(key_id) = contained_key_id {
        protected_header =
            protected_header.value(CONTAINED_KEY_ID, Value::from(Vec::from(&key_id)));
    }

    let protected_header = protected_header.build();

    let cose_encrypt0 = coset::CoseEncrypt0Builder::new()
        .protected(protected_header)
        .create_ciphertext(key_to_seal_bytes, &[], |data, aad| {
            let ciphertext = xchacha20::encrypt_xchacha20_poly1305(
                &(*wrapping_key_inner.enc_key).into(),
                data,
                aad,
            );
            nonce.copy_from_slice(&ciphertext.nonce());
            ciphertext.encrypted_bytes().to_vec()
        })
        .unprotected(HeaderBuilder::new().iv(nonce.to_vec()).build())
        .build();

    Ok(cose_encrypt0)
}

/// Internal helper to unseal a key with a wrapping key.
pub(super) fn unseal_key_internal(
    cose_encrypt0: &coset::CoseEncrypt0,
    wrapping_key: &SymmetricCryptoKey,
    expected_namespace: KeyProtectedKeyEnvelopeNamespace,
) -> Result<Vec<u8>, KeyProtectedKeyEnvelopeError> {
}

/// Extract the namespace from a COSE header.
pub(super) fn extract_envelope_namespace(
    header: &coset::Header,
) -> Result<KeyProtectedKeyEnvelopeNamespace, KeyProtectedKeyEnvelopeError> {
    header
        .rest
        .iter()
        .find_map(|(label, value)| match (label, value) {
            (coset::Label::Int(key), ciborium::Value::Integer(int))
                if *key == KEY_PROTECTED_KEY_ENVELOPE_NAMESPACE =>
            {
                let decoded: i128 = (*int).into();
                Some(KeyProtectedKeyEnvelopeNamespace::try_from(decoded))
            }
            _ => None,
        })
        .unwrap_or_else(|| Err(KeyProtectedKeyEnvelopeError::InvalidNamespace))
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

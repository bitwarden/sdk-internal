#![doc = include_str!("./README.md")]

mod password_protected_key_envelope;
pub use password_protected_key_envelope::*;
mod high_entropy_secret;
pub use high_entropy_secret::*;
mod secret_protected_key_envelope;
pub use secret_protected_key_envelope::*;
mod symmetric_key_envelope;
pub use symmetric_key_envelope::*;
mod data_envelope;
pub use data_envelope::*;
mod key_hierarchy;
pub use key_hierarchy::*;
mod helpers;

use ciborium::Value;

use crate::{
    BitwardenLegacyKeyBytes, ContentFormat, CoseKeyBytes, EncodedSymmetricKey, KEY_ID_SIZE,
    SymmetricCryptoKey,
    cose::{CONTAINED_KEY_ID, extract_bytes},
    keys::KeyId,
    safe::helpers::set_header_value,
};

/// Failure modes when decoding the raw key bytes recovered from a key envelope back into a
/// [`SymmetricCryptoKey`]. See [`decode_sealed_symmetric_key`].
pub(super) enum DecodeSealedKeyError {
    /// The protected header did not declare a valid content format.
    InvalidContentFormat,
    /// The declared content format is not a supported symmetric key encoding.
    UnsupportedContentFormat,
    /// The decoded bytes do not form a valid symmetric key.
    InvalidKey,
}

/// Decodes the raw key bytes recovered from a key envelope into a [`SymmetricCryptoKey`], using the
/// content format declared in the envelope's protected `header`.
///
/// Shared by the key envelopes
/// ([`PasswordProtectedKeyEnvelope`], [`SecretProtectedKeyEnvelope`], and
/// [`SymmetricKeyEnvelope`]), which all store the wrapped key using the same content-format-tagged
/// encoding.
pub(super) fn decode_sealed_symmetric_key(
    header: &coset::Header,
    key_bytes: Vec<u8>,
) -> Result<SymmetricCryptoKey, DecodeSealedKeyError> {
    let encoded_key = match ContentFormat::try_from(header)
        .map_err(|_| DecodeSealedKeyError::InvalidContentFormat)?
    {
        ContentFormat::BitwardenLegacyKey => {
            EncodedSymmetricKey::BitwardenLegacyKey(BitwardenLegacyKeyBytes::from(key_bytes))
        }
        ContentFormat::CoseKey => EncodedSymmetricKey::CoseKey(CoseKeyBytes::from(key_bytes)),
        _ => return Err(DecodeSealedKeyError::UnsupportedContentFormat),
    };
    SymmetricCryptoKey::try_from(encoded_key).map_err(|_| DecodeSealedKeyError::InvalidKey)
}

/// Extract the single recipient from a [`coset::CoseEncrypt`].
///
/// The COSE objects used by this module's envelopes always carry exactly one recipient (holding the
/// KDF parameters). Returns an error if there is not exactly one recipient.
pub(super) fn extract_single_recipient(
    cose_encrypt: &coset::CoseEncrypt,
) -> Result<&coset::CoseRecipient, ()> {
    match cose_encrypt.recipients.as_slice() {
        [recipient] => Ok(recipient),
        _ => Err(()),
    }
}

/// Extract the contained key ID from a COSE header, if present.
/// Only COSE keys have a key ID; legacy keys do not.
pub(super) fn extract_key_id(header: &coset::Header) -> Result<Option<KeyId>, ()> {
    let key_id_bytes = extract_bytes(header, CONTAINED_KEY_ID, "key id");

    if let Ok(bytes) = key_id_bytes {
        let key_id_array: [u8; KEY_ID_SIZE] = bytes.as_slice().try_into().map_err(|_| ())?;
        Ok(Some(KeyId::from(key_id_array)))
    } else {
        Ok(None)
    }
}

/// Set the contained key ID on a COSE header, if present.
pub(super) fn set_contained_key_id(header: &mut coset::Header, key_id: Option<KeyId>) {
    if let Some(key_id) = key_id {
        set_header_value(header, CONTAINED_KEY_ID, Value::from(Vec::from(&key_id)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_contained_key_id_round_trips_through_extract_key_id() {
        let key_id = KeyId::from([7u8; KEY_ID_SIZE]);
        let mut header = coset::HeaderBuilder::new().build();

        set_contained_key_id(&mut header, Some(key_id.clone()));

        assert_eq!(extract_key_id(&header), Ok(Some(key_id)));
    }

    #[test]
    fn extract_key_id_returns_none_when_absent() {
        let header = coset::HeaderBuilder::new().build();

        assert_eq!(extract_key_id(&header), Ok(None));
    }

    #[test]
    fn set_contained_key_id_with_none_leaves_header_without_key_id() {
        let mut header = coset::HeaderBuilder::new().build();

        set_contained_key_id(&mut header, None);

        assert_eq!(extract_key_id(&header), Ok(None));
    }
}

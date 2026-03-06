use bitwarden_core::key_management::{KeyIds, SymmetricKeyId};
use bitwarden_crypto::{
    EncString, KeyStoreContext,
    safe::{DataEnvelope, DataEnvelopeError},
};
use bitwarden_encoding::B64;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{CipherBlob, CipherBlobLatest};
use crate::cipher::blob::v1::CipherBlobV1;

const FORMAT_VERSION: u8 = 1;

/// Error type for `SealedCipherBlob` operations.
#[derive(Debug, Error)]
pub(crate) enum SealedCipherBlobError {
    #[error("Unsupported format version: {0}")]
    UnsupportedFormatVersion(u8),
    #[error("CBOR encoding error")]
    CborEncodingError,
    #[error("CBOR decoding error")]
    CborDecodingError,
    #[error("Base64 decoding error")]
    Base64DecodingError,
    #[error(transparent)]
    DataEnvelope(#[from] DataEnvelopeError),
}

/// Sealed container that packages a wrapped CEK and encrypted `DataEnvelope` together.
///
/// Serializable into the `Cipher.data: Option<String>` field.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct SealedCipherBlob {
    format_version: u8,
    wrapped_cek: EncString,
    envelope: DataEnvelope,
}

impl SealedCipherBlob {
    /// Seals a `CipherBlob` into a `SealedCipherBlob` by encrypting it with a new CEK
    /// wrapped by the provided wrapping key.
    pub(crate) fn seal(
        data: CipherBlob,
        wrapping_key: &SymmetricKeyId,
        ctx: &mut KeyStoreContext<KeyIds>,
    ) -> Result<Self, SealedCipherBlobError> {
        let (envelope, wrapped_cek) =
            DataEnvelope::seal_with_wrapping_key(data, wrapping_key, ctx)?;
        Ok(Self {
            format_version: FORMAT_VERSION,
            wrapped_cek,
            envelope,
        })
    }

    /// Unseals the `CipherBlob` from this container using the provided wrapping key.
    pub(crate) fn unseal(
        &self,
        wrapping_key: &SymmetricKeyId,
        ctx: &mut KeyStoreContext<KeyIds>,
    ) -> Result<CipherBlob, SealedCipherBlobError> {
        if self.format_version != FORMAT_VERSION {
            return Err(SealedCipherBlobError::UnsupportedFormatVersion(
                self.format_version,
            ));
        }
        Ok(self
            .envelope
            .unseal_with_wrapping_key(wrapping_key, &self.wrapped_cek, ctx)?)
    }

    /// Serializes this container into an opaque base64-encoded CBOR string.
    pub(crate) fn to_opaque_string(&self) -> Result<String, SealedCipherBlobError> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(self, &mut buf)
            .map_err(|_| SealedCipherBlobError::CborEncodingError)?;
        Ok(B64::from(buf).to_string())
    }

    /// Deserializes a `SealedCipherBlob` from an opaque base64-encoded CBOR string.
    pub(crate) fn from_opaque_string(s: &str) -> Result<Self, SealedCipherBlobError> {
        let bytes = B64::try_from(s)
            .map_err(|_| SealedCipherBlobError::Base64DecodingError)?
            .into_bytes();
        ciborium::de::from_reader(bytes.as_slice())
            .map_err(|_| SealedCipherBlobError::CborDecodingError)
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::KeyIds;
    use bitwarden_crypto::KeyStore;

    use super::*;
    use crate::cipher::{blob::v1::*, secure_note::SecureNoteType};

    fn test_cipher_blob() -> CipherBlob {
        CipherBlobV1 {
            name: "Test Cipher".to_string(),
            notes: Some("Some notes".to_string()),
            type_data: CipherTypeDataV1::SecureNote(SecureNoteDataV1 {
                r#type: SecureNoteType::Generic,
            }),
            fields: Vec::new(),
            password_history: Vec::new(),
        }
        .into()
    }

    #[test]
    fn test_seal_unseal_round_trip() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let wrapping_key = ctx.generate_symmetric_key();

        let sealed = SealedCipherBlob::seal(test_cipher_blob(), &wrapping_key, &mut ctx).unwrap();
        let unsealed = sealed.unseal(&wrapping_key, &mut ctx).unwrap();

        assert_eq!(test_cipher_blob(), unsealed);
    }

    #[test]
    fn test_opaque_string_round_trip() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let wrapping_key = ctx.generate_symmetric_key();

        let sealed = SealedCipherBlob::seal(test_cipher_blob(), &wrapping_key, &mut ctx).unwrap();

        let opaque = sealed.to_opaque_string().unwrap();
        let restored = SealedCipherBlob::from_opaque_string(&opaque).unwrap();
        let unsealed = restored.unseal(&wrapping_key, &mut ctx).unwrap();

        assert_eq!(test_cipher_blob(), unsealed);
    }

    #[test]
    fn test_unsupported_format_version() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let wrapping_key = ctx.generate_symmetric_key();

        let blob = test_cipher_blob();
        let mut sealed = SealedCipherBlob::seal(blob, &wrapping_key, &mut ctx).unwrap();
        sealed.format_version = 99;

        let result = sealed.unseal(&wrapping_key, &mut ctx);
        assert!(matches!(
            result,
            Err(SealedCipherBlobError::UnsupportedFormatVersion(99))
        ));
    }

    #[test]
    fn test_invalid_base64() {
        let result = SealedCipherBlob::from_opaque_string("not valid base64!@#$");
        assert!(matches!(
            result,
            Err(SealedCipherBlobError::Base64DecodingError)
        ));
    }

    #[test]
    fn test_invalid_cbor() {
        let not_cbor = B64::from(b"this is not valid cbor data".as_slice()).to_string();
        let result = SealedCipherBlob::from_opaque_string(&not_cbor);
        assert!(matches!(
            result,
            Err(SealedCipherBlobError::CborDecodingError)
        ));
    }
}

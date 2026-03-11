use bitwarden_core::key_management::{KeyIds, SymmetricKeyId};
use bitwarden_crypto::{
    EncString, KeyStoreContext,
    safe::{DataEnvelope, DataEnvelopeError},
};
use bitwarden_encoding::B64;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::CipherBlob;

const FORMAT_VERSION: u8 = 1;

/// Error type for `SealedCipherBlob` operations.
#[allow(dead_code)]
#[derive(Debug, Error)]
pub(super) enum SealedCipherBlobError {
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
#[allow(dead_code)]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(super) struct SealedCipherBlob {
    format_version: u8,
    wrapped_cek: EncString,
    envelope: DataEnvelope,
}

#[allow(dead_code)]
impl SealedCipherBlob {
    /// Seals a `CipherBlob` into a `SealedCipherBlob` by encrypting it with a new CEK
    /// wrapped by the provided wrapping key.
    pub(super) fn seal(
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
    pub(super) fn unseal(
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
    pub(super) fn to_opaque_string(&self) -> Result<String, SealedCipherBlobError> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(self, &mut buf)
            .map_err(|_| SealedCipherBlobError::CborEncodingError)?;
        Ok(B64::from(buf).to_string())
    }

    /// Deserializes a `SealedCipherBlob` from an opaque base64-encoded CBOR string.
    pub(super) fn from_opaque_string(s: &str) -> Result<Self, SealedCipherBlobError> {
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
    use bitwarden_crypto::{KeyStore, SymmetricCryptoKey};
    use bitwarden_encoding::B64;

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

    #[test]
    #[ignore]
    fn generate_sealed_test_vector() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let wrapping_key = ctx.generate_symmetric_key();

        let sealed = SealedCipherBlob::seal(test_cipher_blob(), &wrapping_key, &mut ctx).unwrap();
        let opaque = sealed.to_opaque_string().unwrap();

        #[allow(deprecated)]
        let key = ctx.dangerous_get_symmetric_key(wrapping_key).unwrap();
        println!(
            "const TEST_VECTOR_WRAPPING_KEY: &str = \"{}\";",
            key.to_base64()
        );
        println!("const TEST_VECTOR_SEALED_BLOB: &str = \"{}\";", opaque);
    }

    const TEST_VECTOR_WRAPPING_KEY: &str =
        "e0MSZ4/Z4AS7fzjxMos7MXibNALU4mDJQwmge+uVwahg9P25cuaNiSpLvYMk2BgJfntbQs4FszcnY5nPe2FpVA==";
    const TEST_VECTOR_SEALED_BLOB: &str = "o25mb3JtYXRfdmVyc2lvbgFrd3JhcHBlZF9jZWt4tDIub1dJMUloMDVleWxpeGxCQUM4V253QT09fDdOTVFiU3JXS3ZOWFNoTkNHdmZZWld0T2doMEcvZ294YXdod01UWm5PR1hLeVZ6RXA1WWRXRUhoRnQ0UFVrbVVOT204Z2JMRlhyTFN4MW5CU25PdjlEeEJLNFp6ejNJVFp3dm92Z3NBTFQwPXxBMzhlZkFhSlhmMnk2aFdxTHBUanJ6NlF5OS9FRERMWnpJOWZFSGhtVExJPWhlbnZlbG9wZXkBKGcxaExwUUU2QUFFUmJ3TjRJMkZ3Y0d4cFkyRjBhVzl1TDNndVltbDBkMkZ5WkdWdUxtTmliM0l0Y0dGa1pHVmtCRkFQV0dnR1lPblBYVGlNY2NUOVVrVUFPZ0FCT0lFQ09nQUJPSUFCb1FWWUdDeWk1cEtQSHQ2NXAwU0MxR1FGMTZ1TE85SEtUODFmZWxoeFF2UDBrTlYyQXpibks5RXlSUjlSRUUvUURYK0JVcE53bkxjUTZKZldJb2cycHp4TjBBNUlKTmhmZ1Uzd0NMSS9WOVZHcThkM1RZanBLSm9MNitKSVhVQnI0UWtHeGgzekZmci8rQThGN3RwR2dSK0tnLzVQRGJLMk9ENjdkM0ZnOW12b2t2UVBzQ0F5MnlIaVJ6aHdONUU9";

    #[test]
    fn test_recorded_sealed_blob_test_vector() {
        let wrapping_key =
            SymmetricCryptoKey::try_from(B64::try_from(TEST_VECTOR_WRAPPING_KEY).unwrap()).unwrap();

        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let wrapping_key_id = ctx.add_local_symmetric_key(wrapping_key);

        let sealed = SealedCipherBlob::from_opaque_string(TEST_VECTOR_SEALED_BLOB).expect(
            "SealedCipherBlob container format has changed in a backwards-incompatible way. \
             Existing sealed data must remain deserializable.",
        );
        let unsealed = sealed.unseal(&wrapping_key_id, &mut ctx).expect(
            "SealedCipherBlob container format has changed in a backwards-incompatible way. \
             Existing sealed data must remain deserializable.",
        );

        assert_eq!(test_cipher_blob(), unsealed);
    }
}

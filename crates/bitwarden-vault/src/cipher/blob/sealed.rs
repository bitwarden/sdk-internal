use bitwarden_core::key_management::{KeySlotIds, SymmetricKeySlotId};
use bitwarden_crypto::{
    EncString, KeyStoreContext,
    safe::{DataEnvelope, DataEnvelopeError},
};
use bitwarden_logging::instrument;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::CipherBlob;

const FORMAT_VERSION: u8 = 1;

/// Error type for `SealedCipherBlob` operations.
#[derive(Debug, Error)]
pub enum SealedCipherBlobError {
    /// The format version is newer or older than this client supports.
    #[error("Unsupported format version: {0}")]
    UnsupportedFormatVersion(u8),
    /// Serializing the sealed container to JSON failed.
    #[error("JSON encoding error")]
    JsonEncoding,
    /// The string did not parse as a JSON object carrying a `format_version` key.
    #[error("JSON decoding error")]
    JsonDecoding,
    /// The inner `DataEnvelope` could not be sealed or opened.
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
    pub(super) fn seal(
        data: CipherBlob,
        wrapping_key: &SymmetricKeySlotId,
        ctx: &mut KeyStoreContext<KeySlotIds>,
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
    #[instrument(err, fields(format_version = self.format_version))]
    pub(super) fn unseal(
        &self,
        wrapping_key: &SymmetricKeySlotId,
        ctx: &mut KeyStoreContext<KeySlotIds>,
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

    /// Serializes this container into an opaque JSON string.
    pub(super) fn to_opaque_string(&self) -> Result<String, SealedCipherBlobError> {
        serde_json::to_string(self).map_err(|_| SealedCipherBlobError::JsonEncoding)
    }

    /// Deserializes a `SealedCipherBlob` from an opaque JSON string.
    ///
    /// Requires the JSON to be an object carrying a `format_version` key; legacy
    /// field-level `CipherData` never contains it, so it is rejected here.
    pub(super) fn from_opaque_string(s: &str) -> Result<Self, SealedCipherBlobError> {
        let value: serde_json::Value =
            serde_json::from_str(s).map_err(|_| SealedCipherBlobError::JsonDecoding)?;
        if !value
            .as_object()
            .is_some_and(|o| o.contains_key("format_version"))
        {
            return Err(SealedCipherBlobError::JsonDecoding);
        }
        serde_json::from_value(value).map_err(|_| SealedCipherBlobError::JsonDecoding)
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::KeySlotIds;
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
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let wrapping_key = ctx.generate_symmetric_key();

        let sealed = SealedCipherBlob::seal(test_cipher_blob(), &wrapping_key, &mut ctx).unwrap();
        let unsealed = sealed.unseal(&wrapping_key, &mut ctx).unwrap();

        assert_eq!(test_cipher_blob(), unsealed);
    }

    #[test]
    fn test_opaque_string_round_trip() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
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
        let store: KeyStore<KeySlotIds> = KeyStore::default();
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
    fn test_invalid_json() {
        let result = SealedCipherBlob::from_opaque_string("not json");
        assert!(matches!(result, Err(SealedCipherBlobError::JsonDecoding)));
    }

    #[test]
    fn test_missing_format_version() {
        let result = SealedCipherBlob::from_opaque_string("{\"Name\":\"x\"}");
        assert!(matches!(result, Err(SealedCipherBlobError::JsonDecoding)));
    }

    #[test]
    #[ignore]
    fn generate_sealed_test_vector() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
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
        "ytx2yTeNHMbFXIV0Et+PdH12TP6Od/SSJPryvQPqh3xacJI6Z1f3fyRjvNa5mhq/jncIN6KRkv+2j3EaS2D9cA==";
    const TEST_VECTOR_SEALED_BLOB: &str = r#"{"format_version":1,"wrapped_cek":"2.lWM2PaWJINJGmKz4FMN8ew==|bZ5qtkbxjniS1098TVzm63IKQOUgffznGkPP9LqvT5i7Y9wLjlhpxAB2h3icZvgGGtlMBWv5I21GnlcNjG830EBFyC+VaaeJtJoslu0+zpo=|jy4zv45oVDgbBV9N+E38I1KKHgMbZ+agJvGgHH+82Ls=","envelope":"g1hHpQEDA3gjYXBwbGljYXRpb24veC5iaXR3YXJkZW4uY2Jvci1wYWRkZWQEUOsIztihvsPzeLfnHjp76pY6AAE4gQI6AAE4gAGhBUzhTmCubZnEmR36ZJtYcUPFbv7gfSbFKNpQVoO/LB0Rc+xusns6bnK5oX972HnKQ6JRX4lYGrHoXxQFU15WJFqEVFR9QJf3wb3UjdVQ9d0aIGZuPr3H+TGr8rNk0UrEDcPsPrLEoEMkPgXqCwpd9aevAJM/6UqnzsqEK4NSBBTT"}"#;

    #[test]
    fn test_recorded_sealed_blob_test_vector() {
        let wrapping_key =
            SymmetricCryptoKey::try_from(B64::try_from(TEST_VECTOR_WRAPPING_KEY).unwrap()).unwrap();

        let store: KeyStore<KeySlotIds> = KeyStore::default();
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

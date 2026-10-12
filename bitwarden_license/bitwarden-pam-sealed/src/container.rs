//! The opaque wire container shared by both sealed PAM types.
//!
//! Follows the `SealedCipherBlob` precedent in `bitwarden-vault/src/cipher/blob/sealed.rs`: a JSON
//! object carrying a `format_version`, the content-encryption key wrapped by the organization key,
//! and the sealed [`DataEnvelope`]. Namespace separation between [`crate::TargetSystemSealedV1`]
//! and [`crate::RotationConfigSealedV1`] comes from the envelope's own namespace check, not this
//! container.

use bitwarden_crypto::{
    EncString, KeySlotIds, KeyStoreContext,
    safe::{DataEnvelope, DataEnvelopeError, SealableVersionedData},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

const FORMAT_VERSION: u8 = 1;

/// Error sealing or unsealing a PAM data blob.
///
/// Variants never carry field values from the sealed data (e.g. `account_identity`): only the
/// (non-sensitive) format version appears in error output.
#[derive(Debug, Error)]
pub enum SealedDataError {
    /// The format version is newer or older than this client supports.
    #[error("Unsupported format version: {0}")]
    UnsupportedFormatVersion(u8),
    /// Failed to serialize the container to JSON.
    #[error("JSON encoding error")]
    JsonEncoding,
    /// The string did not parse as a JSON object carrying a `format_version` key.
    #[error("JSON decoding error")]
    JsonDecoding,
    /// The inner [`DataEnvelope`] failed to seal or unseal.
    #[error(transparent)]
    DataEnvelope(#[from] DataEnvelopeError),
}

/// Opaque container pairing a wrapped content-encryption key with a sealed [`DataEnvelope`].
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct SealedContainer {
    format_version: u8,
    wrapped_cek: EncString,
    envelope: DataEnvelope,
}

impl SealedContainer {
    /// Seals `data` into a new container, wrapping its content-encryption key with
    /// `wrapping_key` (the organization key).
    pub(crate) fn seal<Ids: KeySlotIds, T>(
        data: T,
        wrapping_key: &Ids::Symmetric,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Self, SealedDataError>
    where
        T: Serialize + SealableVersionedData,
    {
        let (envelope, wrapped_cek) =
            DataEnvelope::seal_with_wrapping_key(data, wrapping_key, ctx)?;
        Ok(Self {
            format_version: FORMAT_VERSION,
            wrapped_cek,
            envelope,
        })
    }

    /// Unseals this container's data using `wrapping_key` (the organization key).
    pub(crate) fn unseal<Ids: KeySlotIds, T>(
        &self,
        wrapping_key: &Ids::Symmetric,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<T, SealedDataError>
    where
        T: DeserializeOwned + SealableVersionedData,
    {
        if self.format_version != FORMAT_VERSION {
            return Err(SealedDataError::UnsupportedFormatVersion(
                self.format_version,
            ));
        }
        Ok(self
            .envelope
            .unseal_with_wrapping_key(wrapping_key, &self.wrapped_cek, ctx)?)
    }

    pub(crate) fn to_opaque_string(&self) -> Result<String, SealedDataError> {
        serde_json::to_string(self).map_err(|_| SealedDataError::JsonEncoding)
    }

    /// Deserializes a container from an opaque JSON string, rejecting payloads that aren't a JSON
    /// object with a `format_version` key up front rather than failing later with a confusing
    /// field-level error.
    pub(crate) fn from_opaque_string(s: &str) -> Result<Self, SealedDataError> {
        let value: serde_json::Value =
            serde_json::from_str(s).map_err(|_| SealedDataError::JsonDecoding)?;
        if !value
            .as_object()
            .is_some_and(|o| o.contains_key("format_version"))
        {
            return Err(SealedDataError::JsonDecoding);
        }
        serde_json::from_value(value).map_err(|_| SealedDataError::JsonDecoding)
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{
        KeyStore, generate_versioned_sealable,
        safe::{DataEnvelopeNamespace, SealableData},
    };
    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::test_support::TestIds;

    /// A minimal sealable payload used only to exercise the shared container.
    #[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
    struct TestPayloadV1 {
        value: u32,
    }
    impl SealableData for TestPayloadV1 {}

    generate_versioned_sealable!(
        TestPayload,
        DataEnvelopeNamespace::PamTargetSystem,
        [
            TestPayloadV1 => "1",
        ]
    );

    #[test]
    fn opaque_string_round_trip() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let wrapping_key = ctx.generate_symmetric_key();

        let payload = TestPayloadV1 { value: 7 };
        let data: TestPayload = payload.clone().into();
        let sealed = SealedContainer::seal(data, &wrapping_key, &mut ctx).unwrap();

        let opaque = sealed.to_opaque_string().unwrap();
        let restored = SealedContainer::from_opaque_string(&opaque).unwrap();
        let unsealed: TestPayload = restored.unseal(&wrapping_key, &mut ctx).unwrap();

        let TestPayload::TestPayloadV1(unsealed) = unsealed;
        assert_eq!(unsealed, payload);
    }

    #[test]
    fn unsupported_format_version() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let wrapping_key = ctx.generate_symmetric_key();

        let data: TestPayload = TestPayloadV1 { value: 1 }.into();
        let mut sealed = SealedContainer::seal(data, &wrapping_key, &mut ctx).unwrap();
        sealed.format_version = 99;

        let result: Result<TestPayload, _> = sealed.unseal(&wrapping_key, &mut ctx);
        assert!(matches!(
            result,
            Err(SealedDataError::UnsupportedFormatVersion(99))
        ));
    }

    #[test]
    fn invalid_json_is_rejected() {
        let result = SealedContainer::from_opaque_string("not json");
        assert!(matches!(result, Err(SealedDataError::JsonDecoding)));
    }

    #[test]
    fn missing_format_version_is_rejected() {
        let result = SealedContainer::from_opaque_string(r#"{"wrapped_cek":"x","envelope":"y"}"#);
        assert!(matches!(result, Err(SealedDataError::JsonDecoding)));
    }
}

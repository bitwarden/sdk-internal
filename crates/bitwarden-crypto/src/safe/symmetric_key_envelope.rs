//! Wrapped symmetric key envelope for sealing a symmetric key with another symmetric key.

use std::str::FromStr;

use bitwarden_encoding::{B64, FromStrVisitor};
use ciborium::Value;
use coset::{CborSerializable, CoseEncrypt0Builder, HeaderBuilder};
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::convert::FromWasmAbi;

use crate::{
    BitwardenLegacyKeyBytes, ContentFormat, CoseKeyBytes, EncodedSymmetricKey, KeyIds,
    KeyStoreContext, SymmetricCryptoKey, XChaCha20Poly1305Key,
    cose::{CONTAINED_KEY_ID, ContentNamespace, SafeObjectNamespace, XCHACHA20_POLY1305},
    keys::KeyId,
    safe::helpers::{
        debug_fmt, extract_contained_key_id, set_safe_namespaces, validate_safe_namespaces,
    },
};

/// Errors that can occur when sealing or unsealing a symmetric key with envelope operations.
#[derive(Debug, Error)]
pub enum SymmetricKeyEnvelopeError {
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
    /// The symmetric key envelope namespace is invalid.
    #[error("Invalid namespace")]
    InvalidNamespace,
}

/// A symmetric key protected by another symmetric key
pub struct SymmetricKeyEnvelope {
    cose_encrypt0: coset::CoseEncrypt0,
}

impl SymmetricKeyEnvelope {
    /// Seals a symmetric key with another symmetric key from the key store.
    ///
    /// This should never fail, except for memory allocation errors.
    pub fn seal<Ids: KeyIds>(
        key_to_seal: Ids::Symmetric,
        sealing_key: Ids::Symmetric,
        namespace: SymmetricKeyEnvelopeNamespace,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<Self, SymmetricKeyEnvelopeError> {
        // Get the keys from the key store.
        let key_to_seal = ctx
            .get_symmetric_key(key_to_seal)
            .map_err(|_| SymmetricKeyEnvelopeError::KeyMissing)?;
        let wrapping_key = ctx
            .get_symmetric_key(sealing_key)
            .map_err(|_| SymmetricKeyEnvelopeError::KeyMissing)?;

        // For now, just XChaCha20Poly1305 is supported as wrapping key
        let wrapping_key: &XChaCha20Poly1305Key = match wrapping_key {
            SymmetricCryptoKey::XChaCha20Poly1305Key(key) => key,
            _ => {
                return Err(SymmetricKeyEnvelopeError::Parsing(
                    "Wrapping key must be XChaCha20Poly1305".to_string(),
                ));
            }
        };

        let (content_format, key_bytes) = match key_to_seal.to_encoded_raw() {
            EncodedSymmetricKey::BitwardenLegacyKey(key_bytes) => {
                (ContentFormat::BitwardenLegacyKey, key_bytes.to_vec())
            }
            EncodedSymmetricKey::CoseKey(key_bytes) => (ContentFormat::CoseKey, key_bytes.to_vec()),
        };

        let mut header_builder = HeaderBuilder::from(content_format);

        // Only set the contained key ID if the key has one
        if let Some(key_id) = key_to_seal.key_id() {
            header_builder =
                header_builder.value(CONTAINED_KEY_ID, Value::from(Vec::from(&key_id)));
        }

        let mut protected_header = header_builder.build();
        set_safe_namespaces(
            &mut protected_header,
            SafeObjectNamespace::SymmetricKeyEnvelope,
            namespace,
        );
        protected_header.alg = Some(coset::Algorithm::PrivateUse(XCHACHA20_POLY1305));
        protected_header.key_id = wrapping_key.key_id.as_slice().into();

        let cose_encrypt0 = crate::cose::encrypt_cose(
            CoseEncrypt0Builder::new().protected(protected_header),
            &key_bytes,
            wrapping_key,
        );

        Ok(SymmetricKeyEnvelope { cose_encrypt0 })
    }

    /// Unseals a symmetric key from the envelope and stores it in the key store context.
    pub fn unseal<Ids: KeyIds>(
        &self,
        wrapping_key: Ids::Symmetric,
        namespace: SymmetricKeyEnvelopeNamespace,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Symmetric, SymmetricKeyEnvelopeError> {
        let wrapping_key_ref = ctx
            .get_symmetric_key(wrapping_key)
            .map_err(|_| SymmetricKeyEnvelopeError::KeyMissing)?;

        let wrapping_key_inner = match wrapping_key_ref {
            SymmetricCryptoKey::XChaCha20Poly1305Key(key) => key,
            _ => {
                return Err(SymmetricKeyEnvelopeError::Parsing(
                    "Wrapping key must be XChaCha20Poly1305".to_string(),
                ));
            }
        };

        validate_safe_namespaces(
            &self.cose_encrypt0.protected.header,
            SafeObjectNamespace::SymmetricKeyEnvelope,
            namespace,
        )
        .map_err(|_| SymmetricKeyEnvelopeError::InvalidNamespace)?;

        // Validate the content format
        let content_format = ContentFormat::try_from(&self.cose_encrypt0.protected.header)
            .map_err(|_| {
                SymmetricKeyEnvelopeError::Parsing("Invalid content format".to_string())
            })?;

        // Decrypt the key bytes
        let key_bytes = crate::cose::decrypt_cose(&self.cose_encrypt0, wrapping_key_inner)
            .map_err(|_| SymmetricKeyEnvelopeError::WrongKey)?;

        // Reconstruct the encoded symmetric key from the content format
        let encoded_key = match content_format {
            ContentFormat::BitwardenLegacyKey => {
                EncodedSymmetricKey::BitwardenLegacyKey(BitwardenLegacyKeyBytes::from(key_bytes))
            }
            ContentFormat::CoseKey => EncodedSymmetricKey::CoseKey(CoseKeyBytes::from(key_bytes)),
            _ => {
                return Err(SymmetricKeyEnvelopeError::WrongKeyType);
            }
        };

        let key = SymmetricCryptoKey::try_from(encoded_key)
            .map_err(|_| SymmetricKeyEnvelopeError::WrongKeyType)?;

        Ok(ctx.add_local_symmetric_key(key))
    }

    /// Get the key ID of the contained key.
    pub fn contained_key_id(&self) -> Result<Option<KeyId>, SymmetricKeyEnvelopeError> {
        extract_contained_key_id(&self.cose_encrypt0.protected.header)
            .map_err(|_| SymmetricKeyEnvelopeError::Parsing("Invalid contained key id".to_string()))
    }
}

impl From<&SymmetricKeyEnvelope> for Vec<u8> {
    fn from(val: &SymmetricKeyEnvelope) -> Self {
        val.cose_encrypt0
            .clone()
            .to_vec()
            .expect("Serialization to cose should not fail")
    }
}

impl TryFrom<&Vec<u8>> for SymmetricKeyEnvelope {
    type Error = coset::CoseError;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        let cose_encrypt0 = coset::CoseEncrypt0::from_slice(value)?;
        Ok(SymmetricKeyEnvelope { cose_encrypt0 })
    }
}

impl std::fmt::Debug for SymmetricKeyEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("SymmetricKeyEnvelope");

        if !self.cose_encrypt0.protected.header.key_id.is_empty() {
            s.field(
                "sealing_key_id",
                &self.cose_encrypt0.protected.header.key_id,
            );
        }

        debug_fmt::<SymmetricKeyEnvelopeNamespace>(&mut s, &self.cose_encrypt0.protected.header);

        if let Ok(Some(key_id)) = self.contained_key_id() {
            s.field("contained_key_id", &key_id);
        }

        s.finish()
    }
}

impl FromStr for SymmetricKeyEnvelope {
    type Err = SymmetricKeyEnvelopeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = B64::try_from(s).map_err(|_| {
            SymmetricKeyEnvelopeError::Parsing(
                "Invalid WrappedSymmetricKey Base64 encoding".to_string(),
            )
        })?;
        Self::try_from(&data.into_bytes()).map_err(|_| {
            SymmetricKeyEnvelopeError::Parsing("Failed to parse SymmetricKeyEnvelope".to_string())
        })
    }
}

impl From<SymmetricKeyEnvelope> for String {
    fn from(val: SymmetricKeyEnvelope) -> Self {
        let serialized: Vec<u8> = (&val).into();
        B64::from(serialized).to_string()
    }
}

impl<'de> Deserialize<'de> for SymmetricKeyEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new())
    }
}

impl Serialize for SymmetricKeyEnvelope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let serialized: Vec<u8> = self.into();
        serializer.serialize_str(&B64::from(serialized).to_string())
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export type SymmetricKeyEnvelope = Tagged<string, "SymmetricKeyEnvelope">;
"#;

#[cfg(feature = "wasm")]
impl wasm_bindgen::describe::WasmDescribe for SymmetricKeyEnvelope {
    fn describe() {
        <String as wasm_bindgen::describe::WasmDescribe>::describe();
    }
}

#[cfg(feature = "wasm")]
impl FromWasmAbi for SymmetricKeyEnvelope {
    type Abi = <String as FromWasmAbi>::Abi;

    unsafe fn from_abi(abi: Self::Abi) -> Self {
        use wasm_bindgen::UnwrapThrowExt;
        let string = unsafe { String::from_abi(abi) };
        SymmetricKeyEnvelope::from_str(&string).unwrap_throw()
    }
}

/// Content namespace for the symmetric key envelope
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum SymmetricKeyEnvelopeNamespace {
    /// A key used for re-hydration of the SDK
    SessionKey = 1,
    #[cfg(test)]
    /// Example namespace for testing purposes.
    ExampleNamespace = -3,
    #[cfg(test)]
    /// Another example namespace for testing purposes.
    ExampleNamespace2 = -4,
}

impl SymmetricKeyEnvelopeNamespace {
    /// Returns the numeric value of the namespace.
    pub fn as_i64(&self) -> i64 {
        *self as i64
    }
}

impl TryFrom<i128> for SymmetricKeyEnvelopeNamespace {
    type Error = SymmetricKeyEnvelopeError;

    fn try_from(value: i128) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(SymmetricKeyEnvelopeNamespace::SessionKey),
            #[cfg(test)]
            -3 => Ok(SymmetricKeyEnvelopeNamespace::ExampleNamespace),
            #[cfg(test)]
            -4 => Ok(SymmetricKeyEnvelopeNamespace::ExampleNamespace2),
            _ => Err(SymmetricKeyEnvelopeError::InvalidNamespace),
        }
    }
}

impl TryFrom<i64> for SymmetricKeyEnvelopeNamespace {
    type Error = SymmetricKeyEnvelopeError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        Self::try_from(i128::from(value))
    }
}

impl From<SymmetricKeyEnvelopeNamespace> for i128 {
    fn from(value: SymmetricKeyEnvelopeNamespace) -> Self {
        value.as_i64().into()
    }
}

impl ContentNamespace for SymmetricKeyEnvelopeNamespace {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KeyStore, SymmetricKeyAlgorithm, traits::tests::TestIds};

    const TEST_VECTOR_SEALING_KEY: &str = "pQEEAlBLD8tcKNRLZaXNSr8OcwkgAzoAARFvBIQDBAUGIFgggG++dwvSRVPaPrIis1+XXXCizFYcakDZxSJP2HlJj0YB";
    const TEST_VECTOR_KEY_TO_SEAL: &str = "pQEEAlCEjXxxMulOVJtq1CSNv1aqAzoAARFvBIQDBAUGIFggwdF1yfFVwesj1CMQlVMhm+tvjwA1pxvTnQVUmfBMlJMB";
    const TEST_VECTOR_ENVELOPE: &str = "g1gspQE6AAERbwMYZToAATiBAzoAATiAIjoAARVcUISNfHEy6U5Um2rUJI2/VqqhBVgYnGokg0NPDLDd18K13zYsAM1SN+NkcfSJWFSEgtR3nhrJzUHRq35myF0tZh18iQx+0vJQ2BHj4lWwHLV3awLcyxdD8UBNQYgKu6nDHs1KDiFN+D48iI60aelHmLgJpNVsCBovnTxZVLbo67AIgw4=";

    #[test]
    #[ignore = "Manual test to verify debug format"]
    fn test_debug() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let key1 = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let key2 = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        let envelope = SymmetricKeyEnvelope::seal(
            key1,
            key2,
            SymmetricKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        );
        println!("{:?}", envelope);
    }

    #[test]
    fn test_seal_unseal_symmetric() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        let envelope = SymmetricKeyEnvelope::seal(
            key_to_seal,
            wrapping_key,
            SymmetricKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        let unsealed_key = envelope
            .unseal(
                wrapping_key,
                SymmetricKeyEnvelopeNamespace::ExampleNamespace,
                &mut ctx,
            )
            .unwrap();

        let unsealed_key_ref = ctx
            .get_symmetric_key(unsealed_key)
            .expect("Key should exist in the key store");

        let original_key_ref = ctx
            .get_symmetric_key(key_to_seal)
            .expect("Key should exist in the key store");

        assert_eq!(unsealed_key_ref, original_key_ref);
    }

    #[test]
    fn test_contained_key_id_symmetric() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        let envelope = SymmetricKeyEnvelope::seal(
            key_to_seal,
            wrapping_key,
            SymmetricKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        let key_to_seal_ref = ctx
            .get_symmetric_key(key_to_seal)
            .expect("Key should exist in the key store");

        let contained_key_id = envelope.contained_key_id().unwrap();

        assert_eq!(key_to_seal_ref.key_id(), contained_key_id);
    }

    #[test]
    fn test_string_serialization() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        let envelope = SymmetricKeyEnvelope::seal(
            key_to_seal,
            wrapping_key,
            SymmetricKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        let serialized: String = envelope.into();
        let deserialized = SymmetricKeyEnvelope::from_str(&serialized).unwrap();

        let unsealed_key = deserialized
            .unseal(
                wrapping_key,
                SymmetricKeyEnvelopeNamespace::ExampleNamespace,
                &mut ctx,
            )
            .unwrap();

        let unsealed_key_ref = ctx
            .get_symmetric_key(unsealed_key)
            .expect("Key should exist in the key store");

        let original_key_ref = ctx
            .get_symmetric_key(key_to_seal)
            .expect("Key should exist in the key store");

        assert_eq!(unsealed_key_ref, original_key_ref);
    }

    #[test]
    fn test_wrong_key() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let wrong_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        let envelope = SymmetricKeyEnvelope::seal(
            key_to_seal,
            wrapping_key,
            SymmetricKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        assert!(matches!(
            envelope.unseal(
                wrong_key,
                SymmetricKeyEnvelopeNamespace::ExampleNamespace,
                &mut ctx
            ),
            Err(SymmetricKeyEnvelopeError::WrongKey)
        ));
    }

    #[test]
    fn test_wrong_namespace() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        let envelope = SymmetricKeyEnvelope::seal(
            key_to_seal,
            wrapping_key,
            SymmetricKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        assert!(matches!(
            envelope.unseal(
                wrapping_key,
                SymmetricKeyEnvelopeNamespace::ExampleNamespace2,
                &mut ctx
            ),
            Err(SymmetricKeyEnvelopeError::InvalidNamespace)
        ));
    }

    #[test]
    #[ignore]
    fn generate_test_vectors() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        let envelope = SymmetricKeyEnvelope::seal(
            key_to_seal,
            wrapping_key,
            SymmetricKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        println!(
            "const TEST_VECTOR_SEALING_KEY: &str = \"{}\";",
            bitwarden_encoding::B64::from(
                ctx.get_symmetric_key(wrapping_key)
                    .unwrap()
                    .to_encoded()
                    .to_vec()
                    .as_slice()
            )
        );
        println!(
            "const TEST_VECTOR_KEY_TO_SEAL: &str = \"{}\";",
            bitwarden_encoding::B64::from(
                ctx.get_symmetric_key(key_to_seal)
                    .unwrap()
                    .to_encoded()
                    .to_vec()
                    .as_slice()
            )
        );
        let serialized: String = envelope.into();
        println!("const TEST_VECTOR_ENVELOPE: &str = \"{}\";", serialized);
    }

    #[test]
    fn decrypt_test_vectors() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let sealing_key = SymmetricCryptoKey::try_from(TEST_VECTOR_SEALING_KEY.to_string())
            .expect("Failed to parse sealing key from test vector");
        let sealed_key_test_vector =
            SymmetricCryptoKey::try_from(TEST_VECTOR_KEY_TO_SEAL.to_string())
                .expect("Failed to parse key to seal from test vector");

        let sealing_key_id = ctx.add_local_symmetric_key(sealing_key);

        let envelope = SymmetricKeyEnvelope::from_str(TEST_VECTOR_ENVELOPE).unwrap();

        let unsealed_key_id = envelope
            .unseal(
                sealing_key_id,
                SymmetricKeyEnvelopeNamespace::ExampleNamespace,
                &mut ctx,
            )
            .unwrap();
        let unsealed_key = ctx.get_symmetric_key(unsealed_key_id).unwrap();
        assert_eq!(unsealed_key.to_owned(), sealed_key_test_vector.to_owned());
    }
}

//! Wrapped symmetric key envelope for sealing a symmetric key with another symmetric key.

use std::str::FromStr;

use bitwarden_encoding::{B64, FromStrVisitor};
use coset::{CborSerializable, CoseEncrypt0Builder, HeaderBuilder};
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::convert::FromWasmAbi;

use crate::{
    ContentFormat, EncodedSymmetricKey, KeySlotIds, KeyStoreContext, SymmetricCryptoKey,
    XAes256GcmKey,
    cose::{
        ContentNamespace, SafeObjectNamespace,
        symmetric::{
            CoseAlgorithmPolicy, CoseContentEncryptionAlgorithm, decrypt_cose0, encrypt_cose0,
        },
    },
    keys::KeyId,
    safe::{
        DecodeSealedKeyError, KeyEncryptionKey, decode_sealed_symmetric_key, extract_key_id,
        helpers::{debug_fmt, set_safe_namespaces, validate_safe_namespaces},
        set_contained_key_id,
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
    /// A wrapping or contained key has an unsupported type
    #[error("Wrong key type")]
    WrongKeyType,
    /// The symmetric key envelope namespace is invalid.
    #[error("Invalid namespace")]
    InvalidNamespace,
}

/// A symmetric key protected by an XAES-256-GCM wrapping key.
#[derive(Clone)]
pub struct SymmetricKeyEnvelope {
    cose_encrypt0: coset::CoseEncrypt0,
}

impl SymmetricKeyEnvelope {
    /// Seals a symmetric key with an XAES-256-GCM key from the key store.
    pub fn seal<Ids: KeySlotIds>(
        key_to_seal: Ids::Symmetric,
        sealing_key: Ids::Symmetric,
        namespace: SymmetricKeyEnvelopeNamespace,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<Self, SymmetricKeyEnvelopeError> {
        if !KeyEncryptionKey::is_key_algorithm_valid(ctx, sealing_key) {
            return Err(SymmetricKeyEnvelopeError::WrongKeyType);
        }

        // Get the keys from the key store.
        let key_to_seal = ctx
            .get_symmetric_key(key_to_seal)
            .map_err(|_| SymmetricKeyEnvelopeError::KeyMissing)?;
        let wrapping_key = ctx
            .get_symmetric_key(sealing_key)
            .map_err(|_| SymmetricKeyEnvelopeError::KeyMissing)?;

        let wrapping_key: &XAes256GcmKey = match wrapping_key {
            SymmetricCryptoKey::XAes256GcmKey(key) => key,
            _ => return Err(SymmetricKeyEnvelopeError::WrongKeyType),
        };

        let (content_format, key_bytes) = match key_to_seal.to_encoded_raw() {
            EncodedSymmetricKey::BitwardenLegacyKey(key_bytes) => {
                (ContentFormat::BitwardenLegacyKey, key_bytes.to_vec())
            }
            EncodedSymmetricKey::CoseKey(key_bytes) => (ContentFormat::CoseKey, key_bytes.to_vec()),
        };

        let mut protected_header = HeaderBuilder::from(content_format).build();

        set_contained_key_id(&mut protected_header, key_to_seal.key_id());

        set_safe_namespaces(
            &mut protected_header,
            SafeObjectNamespace::SymmetricKeyEnvelope,
            namespace,
        );
        protected_header.key_id = wrapping_key.key_id.as_slice().into();

        let cose_encrypt0 = encrypt_cose0(
            CoseContentEncryptionAlgorithm::XAes256Gcm,
            CoseEncrypt0Builder::new(),
            protected_header,
            &key_bytes,
            wrapping_key.enc_key.as_slice(),
        )
        .map_err(|_| SymmetricKeyEnvelopeError::WrongKeyType)?;

        Ok(SymmetricKeyEnvelope { cose_encrypt0 })
    }

    /// Unseals a symmetric key with an XAES-256-GCM key and stores it in the key store context.
    pub fn unseal<Ids: KeySlotIds>(
        &self,
        wrapping_key: Ids::Symmetric,
        namespace: SymmetricKeyEnvelopeNamespace,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Symmetric, SymmetricKeyEnvelopeError> {
        let wrapping_key_ref = ctx
            .get_symmetric_key(wrapping_key)
            .map_err(|_| SymmetricKeyEnvelopeError::KeyMissing)?;

        let wrapping_key_inner = match wrapping_key_ref {
            SymmetricCryptoKey::XAes256GcmKey(key) => key,
            _ => return Err(SymmetricKeyEnvelopeError::WrongKeyType),
        };

        validate_safe_namespaces(
            &self.cose_encrypt0.protected.header,
            SafeObjectNamespace::SymmetricKeyEnvelope,
            namespace,
        )
        .map_err(|_| SymmetricKeyEnvelopeError::InvalidNamespace)?;

        // The wrapping key is independently typed as XAES-256-GCM, so require the protected
        // content-encryption algorithm to match it before attempting decryption.
        let key_bytes = decrypt_cose0(
            &self.cose_encrypt0,
            CoseAlgorithmPolicy::Exactly(CoseContentEncryptionAlgorithm::XAes256Gcm),
            wrapping_key_inner.enc_key.as_slice(),
        )
        .map_err(|_| SymmetricKeyEnvelopeError::WrongKey)?;

        let key = decode_sealed_symmetric_key(&self.cose_encrypt0.protected.header, key_bytes)
            .map_err(|e| match e {
                DecodeSealedKeyError::InvalidContentFormat => {
                    SymmetricKeyEnvelopeError::Parsing("Invalid content format".to_string())
                }
                DecodeSealedKeyError::UnsupportedContentFormat
                | DecodeSealedKeyError::InvalidKey => SymmetricKeyEnvelopeError::WrongKeyType,
            })?;

        Ok(ctx.add_local_symmetric_key(key))
    }

    /// Get the key ID of the contained key.
    pub fn contained_key_id(&self) -> Result<Option<KeyId>, SymmetricKeyEnvelopeError> {
        extract_key_id(&self.cose_encrypt0.protected.header)
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
    /// Organization member invites. Used to seal the invite-data content-encryption key and the
    /// organization key with the invite key.
    OrganizationInvite = 2,
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
            2 => Ok(SymmetricKeyEnvelopeNamespace::OrganizationInvite),
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

    const TEST_VECTOR_SEALING_KEY: &str = "pQEEAlAJiRm3TVKQVUpm9gqA4tm6AzoAARF5BIQDBAUGIFggQyO5bN7Uto3hpXUyqluuArn+zppBmhdnahDRJ6p4s84B";
    const TEST_VECTOR_KEY_TO_SEAL: &str = "pQEEAlDpQoswNPD5xaz7sYLHZXXXAzoAARFvBIQDBAUGIFgg2YO7eUZhb9WSxxsGvdURTunDOBV0W4FRk9E4TV7c00QB";
    const TEST_VECTOR_ENVELOPE: &str = "g1g+pgE6AAEReQMYZQRQCYkZt01SkFVKZvYKgOLZujoAARVcUOlCizA08PnFrPuxgsdlddc6AAE4gQM6AAE4gCKhBVgYLLX2iYq+Ko+2Hp2fByDfGd5AC0Lw4+zxWFS9n8fBbBKHfiarETj6Q3uRwZYpDS5p29MBEJW7WxOaf5Az51+Qtr8ugnoocUJhb8l6vmkDxFy1blU6iHuoBvpd+3MSFOeCdiuMLbKrf469fmUlDn0=";

    #[test]
    #[ignore = "Manual test to verify debug format"]
    fn test_debug() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let key1 = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let key2 = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);

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
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);

        let envelope = SymmetricKeyEnvelope::seal(
            key_to_seal,
            wrapping_key,
            SymmetricKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        assert_eq!(
            envelope.cose_encrypt0.protected.header.alg,
            Some(coset::Algorithm::PrivateUse(crate::cose::XAES_256_GCM))
        );

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
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);

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
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);

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
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
        let wrong_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);

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
    fn test_rejects_non_xaes_wrapping_keys() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
        let envelope = SymmetricKeyEnvelope::seal(
            key_to_seal,
            wrapping_key,
            SymmetricKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        let unsupported_wrapping_keys = [
            ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac),
            ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256Gcm),
            ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305),
        ];

        for unsupported_wrapping_key in unsupported_wrapping_keys {
            assert!(matches!(
                SymmetricKeyEnvelope::seal(
                    key_to_seal,
                    unsupported_wrapping_key,
                    SymmetricKeyEnvelopeNamespace::ExampleNamespace,
                    &ctx,
                ),
                Err(SymmetricKeyEnvelopeError::WrongKeyType)
            ));
            assert!(matches!(
                envelope.unseal(
                    unsupported_wrapping_key,
                    SymmetricKeyEnvelopeNamespace::ExampleNamespace,
                    &mut ctx,
                ),
                Err(SymmetricKeyEnvelopeError::WrongKeyType)
            ));
        }
    }

    #[test]
    fn test_wrong_namespace() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);

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
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);

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

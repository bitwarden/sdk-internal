//! Wrapped signing key envelope for sealing a signing key with a symmetric key.

use std::str::FromStr;

use bitwarden_encoding::{B64, FromStrVisitor};
use ciborium::{Value, value::Integer};
use coset::{CborSerializable, CoseEncrypt0Builder, HeaderBuilder};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use wasm_bindgen::convert::FromWasmAbi;

use super::cose_envelope_helpers::*;
use crate::{
    ContentFormat, CoseKeyBytes, KeyIds, KeyStoreContext, SigningKey, SymmetricCryptoKey,
    XChaCha20Poly1305Key,
    cose::{
        CONTAINED_KEY_ID, CONTENT_NAMESPACE, CoseSerializable, SAFE_OBJECT_NAMESPACE,
        SafeObjectNamespace, XCHACHA20_POLY1305,
    },
    keys::KeyId,
};

#[derive(Copy, Clone)]
pub enum Namespace {
    #[cfg(test)]
    /// Example namespace for testing purposes.
    ExampleNamespace = -3,
    #[cfg(test)]
    /// Another example namespace for testing purposes.
    ExampleNamespace2 = -4,
}

impl Namespace {
    /// Returns the numeric value of the namespace.
    pub fn as_i64(&self) -> i64 {
        *self as i64
    }
}

/// A wrapped signing key
pub struct WrappedSigningKey {
    cose_encrypt0: coset::CoseEncrypt0,
}

impl WrappedSigningKey {
    /// Seals a signing key with a symmetric key from the key store.
    ///
    /// This should never fail, except for memory allocation errors.
    pub fn seal<Ids: KeyIds>(
        key_to_seal: Ids::Signing,
        wrapping_key: Ids::Symmetric,
        namespace: Namespace,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<Self, KeyProtectedKeyEnvelopeError> {
        // Get the keys from the key store.
        let key_to_seal = ctx
            .get_signing_key(key_to_seal)
            .map_err(|_| KeyProtectedKeyEnvelopeError::KeyMissing)?;
        let wrapping_key = ctx
            .get_symmetric_key(wrapping_key)
            .map_err(|_| KeyProtectedKeyEnvelopeError::KeyMissing)?;

        // For now, just XChaCha20Poly1305 is supported
        let wrapping_key: &XChaCha20Poly1305Key = match wrapping_key {
            SymmetricCryptoKey::XChaCha20Poly1305Key(key) => key,
            _ => {
                return Err(KeyProtectedKeyEnvelopeError::Parsing(
                    "Wrapping key must be XChaCha20Poly1305".to_string(),
                ));
            }
        };

        let key_bytes = key_to_seal.to_cose();

        let mut protected_header = HeaderBuilder::from(ContentFormat::CoseKey)
            .value(
                SAFE_OBJECT_NAMESPACE,
                Value::from(SafeObjectNamespace::WrappedSigningKeyNamespace as i64),
            )
            .value(
                CONTENT_NAMESPACE,
                Value::Integer(Integer::from(namespace.as_i64())),
            )
            .value(
                CONTAINED_KEY_ID,
                Value::from(Vec::from(&key_to_seal.key_id())),
            )
            .build();
        protected_header.alg = Some(coset::Algorithm::PrivateUse(XCHACHA20_POLY1305));

        let cose_encrypt0 = crate::cose::encrypt_cose(
            CoseEncrypt0Builder::new().protected(protected_header),
            key_bytes.as_ref(),
            wrapping_key,
        );

        Ok(WrappedSigningKey { cose_encrypt0 })
    }

    /// Unseals a signing key from the envelope and stores it in the key store context.
    pub fn unseal<Ids: KeyIds>(
        &self,
        wrapping_key: Ids::Symmetric,
        namespace: Namespace,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Signing, KeyProtectedKeyEnvelopeError> {
        let wrapping_key_ref = ctx
            .get_symmetric_key(wrapping_key)
            .map_err(|_| KeyProtectedKeyEnvelopeError::KeyMissing)?;

        let wrapping_key_inner = match wrapping_key_ref {
            SymmetricCryptoKey::XChaCha20Poly1305Key(key) => key,
            _ => {
                return Err(KeyProtectedKeyEnvelopeError::Parsing(
                    "Wrapping key must be XChaCha20Poly1305".to_string(),
                ));
            }
        };

        // Validate the safe object namespace
        let safe_object_namespace =
            extract_safe_object_namespace(&self.cose_encrypt0.protected.header)?;
        if safe_object_namespace != SafeObjectNamespace::WrappedSigningKeyNamespace as i64 {
            return Err(KeyProtectedKeyEnvelopeError::InvalidNamespace);
        }

        // Validate the content namespace
        let envelope_namespace = extract_envelope_namespace(&self.cose_encrypt0.protected.header)?;
        if envelope_namespace != namespace.as_i64() {
            return Err(KeyProtectedKeyEnvelopeError::InvalidNamespace);
        }

        // Validate the content format
        let content_format = ContentFormat::try_from(&self.cose_encrypt0.protected.header)
            .map_err(|_| {
                KeyProtectedKeyEnvelopeError::Parsing("Invalid content format".to_string())
            })?;
        if content_format != ContentFormat::CoseKey {
            return Err(KeyProtectedKeyEnvelopeError::WrongKeyType);
        }

        // Decrypt the key bytes
        let key_bytes = crate::cose::decrypt_cose(&self.cose_encrypt0, wrapping_key_inner)
            .map_err(|_| KeyProtectedKeyEnvelopeError::WrongKey)?;

        let key = SigningKey::from_cose(&CoseKeyBytes::from(key_bytes)).map_err(|_| {
            KeyProtectedKeyEnvelopeError::Parsing("Failed to decode signing key".to_string())
        })?;

        Ok(ctx.add_local_signing_key(key))
    }

    /// Get the key ID of the contained key.
    pub fn contained_key_id(&self) -> Result<Option<KeyId>, KeyProtectedKeyEnvelopeError> {
        extract_contained_key_id(&self.cose_encrypt0.protected.header)
    }
}

impl From<&WrappedSigningKey> for Vec<u8> {
    fn from(val: &WrappedSigningKey) -> Self {
        val.cose_encrypt0
            .clone()
            .to_vec()
            .expect("Serialization to cose should not fail")
    }
}

impl TryFrom<&Vec<u8>> for WrappedSigningKey {
    type Error = coset::CoseError;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        let cose_encrypt0 = coset::CoseEncrypt0::from_slice(value)?;
        Ok(WrappedSigningKey { cose_encrypt0 })
    }
}

impl std::fmt::Debug for WrappedSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WrappedSigningKey")
            .field("cose_encrypt0", &self.cose_encrypt0)
            .finish()
    }
}

impl FromStr for WrappedSigningKey {
    type Err = KeyProtectedKeyEnvelopeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = B64::try_from(s).map_err(|_| {
            KeyProtectedKeyEnvelopeError::Parsing(
                "Invalid WrappedSigningKey Base64 encoding".to_string(),
            )
        })?;
        Self::try_from(&data.into_bytes()).map_err(|_| {
            KeyProtectedKeyEnvelopeError::Parsing("Failed to parse WrappedSigningKey".to_string())
        })
    }
}

impl From<WrappedSigningKey> for String {
    fn from(val: WrappedSigningKey) -> Self {
        let serialized: Vec<u8> = (&val).into();
        B64::from(serialized).to_string()
    }
}

impl<'de> Deserialize<'de> for WrappedSigningKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new())
    }
}

impl Serialize for WrappedSigningKey {
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
export type WrappedSigningKey = Tagged<string, "WrappedSigningKey">;
"#;

#[cfg(feature = "wasm")]
impl wasm_bindgen::describe::WasmDescribe for WrappedSigningKey {
    fn describe() {
        <String as wasm_bindgen::describe::WasmDescribe>::describe();
    }
}

#[cfg(feature = "wasm")]
impl FromWasmAbi for WrappedSigningKey {
    type Abi = <String as FromWasmAbi>::Abi;

    unsafe fn from_abi(abi: Self::Abi) -> Self {
        use wasm_bindgen::UnwrapThrowExt;
        let string = unsafe { String::from_abi(abi) };
        WrappedSigningKey::from_str(&string).unwrap_throw()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KeyStore, SignatureAlgorithm, SymmetricKeyAlgorithm, traits::tests::TestIds};

    #[test]
    fn test_seal_unseal_signing() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_signing_key(SignatureAlgorithm::Ed25519);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        let envelope =
            WrappedSigningKey::seal(key_to_seal, wrapping_key, Namespace::ExampleNamespace, &ctx)
                .unwrap();

        let unsealed_key = envelope
            .unseal(wrapping_key, Namespace::ExampleNamespace, &mut ctx)
            .unwrap();

        #[allow(deprecated)]
        let unsealed_key_ref = ctx
            .get_signing_key(unsealed_key)
            .expect("Key should exist in the key store");

        #[allow(deprecated)]
        let original_key_ref = ctx
            .get_signing_key(key_to_seal)
            .expect("Key should exist in the key store");

        assert_eq!(unsealed_key_ref.to_cose(), original_key_ref.to_cose());
    }

    #[test]
    fn test_contained_key_id_signing() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_signing_key(SignatureAlgorithm::Ed25519);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        let envelope =
            WrappedSigningKey::seal(key_to_seal, wrapping_key, Namespace::ExampleNamespace, &ctx)
                .unwrap();

        #[allow(deprecated)]
        let key_to_seal_ref = ctx
            .get_signing_key(key_to_seal)
            .expect("Key should exist in the key store");

        let contained_key_id = envelope.contained_key_id().unwrap();

        assert_eq!(Some(key_to_seal_ref.key_id()), contained_key_id);
    }

    #[test]
    fn test_string_serialization() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_signing_key(SignatureAlgorithm::Ed25519);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        let envelope =
            WrappedSigningKey::seal(key_to_seal, wrapping_key, Namespace::ExampleNamespace, &ctx)
                .unwrap();

        let serialized: String = envelope.into();
        let deserialized = WrappedSigningKey::from_str(&serialized).unwrap();

        let unsealed_key = deserialized
            .unseal(wrapping_key, Namespace::ExampleNamespace, &mut ctx)
            .unwrap();

        #[allow(deprecated)]
        let unsealed_key_ref = ctx
            .get_signing_key(unsealed_key)
            .expect("Key should exist in the key store");

        #[allow(deprecated)]
        let original_key_ref = ctx
            .get_signing_key(key_to_seal)
            .expect("Key should exist in the key store");

        assert_eq!(unsealed_key_ref.to_cose(), original_key_ref.to_cose());
    }

    #[test]
    fn test_wrong_key() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_signing_key(SignatureAlgorithm::Ed25519);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let wrong_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        let envelope =
            WrappedSigningKey::seal(key_to_seal, wrapping_key, Namespace::ExampleNamespace, &ctx)
                .unwrap();

        assert!(matches!(
            envelope.unseal(wrong_key, Namespace::ExampleNamespace, &mut ctx),
            Err(KeyProtectedKeyEnvelopeError::WrongKey)
        ));
    }

    #[test]
    fn test_wrong_namespace() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_signing_key(SignatureAlgorithm::Ed25519);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        let envelope =
            WrappedSigningKey::seal(key_to_seal, wrapping_key, Namespace::ExampleNamespace, &ctx)
                .unwrap();

        assert!(matches!(
            envelope.unseal(wrapping_key, Namespace::ExampleNamespace2, &mut ctx),
            Err(KeyProtectedKeyEnvelopeError::InvalidNamespace)
        ));
    }
}

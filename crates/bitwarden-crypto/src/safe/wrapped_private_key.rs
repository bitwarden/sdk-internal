//! Wrapped private key envelope for sealing a private key with a symmetric key.

use std::str::FromStr;

use bitwarden_encoding::{B64, FromStrVisitor};
use ciborium::Value;
use coset::{CborSerializable, CoseEncrypt0Builder, HeaderBuilder};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use wasm_bindgen::convert::FromWasmAbi;

use crate::{
    ContentFormat, CoseKeyBytes, KeyIds, KeyStoreContext, PrivateKey, SymmetricCryptoKey,
    XChaCha20Poly1305Key,
    cose::{CONTAINED_KEY_ID, CoseSerializable, encrypt_cose},
    keys::KeyId,
};

use super::cose_envelope_helpers::*;

pub enum PrivateKeyNamespace {
    UserPrivateKey,
    OrganizationPrivateKey,
}

// A wrapped private key.
pub struct WrappedPrivateKey {
    cose_encrypt0: coset::CoseEncrypt0,
}

impl WrappedPrivateKey {
    /// Seals a private key with a symmetric key from the key store.
    ///
    /// This should never fail, except for memory allocation errors.
    pub fn seal<Ids: KeyIds>(
        key_to_seal: Ids::Private,
        wrapping_key: Ids::Symmetric,
        namespace: PrivateKeyNamespace,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<Self, KeyProtectedKeyEnvelopeError> {
        // Get the keys from the key store.
        let key_to_seal = ctx
            .get_private_key(key_to_seal)
            .map_err(|_| KeyProtectedKeyEnvelopeError::KeyMissing)?;
        let wrapping_key = ctx
            .get_symmetric_key(wrapping_key)
            .map_err(|_| KeyProtectedKeyEnvelopeError::KeyMissing)?;

        // For now, just XChaCha20Poly1305 is supported
        let wrapping_key: XChaCha20Poly1305Key = match wrapping_key {
            SymmetricCryptoKey::XChaCha20Poly1305Key(key) => key.to_owned(),
            _ => {
                return Err(KeyProtectedKeyEnvelopeError::Parsing(
                    "Wrapping key must be XChaCha20Poly1305".to_string(),
                ));
            }
        };

        let protected_header = HeaderBuilder::from(ContentFormat::CoseKey)
            .value(
                CONTAINED_KEY_ID,
                Value::from(Vec::from(&key_to_seal.key_id())),
            )
            .build();
        let encrypt0_builder = CoseEncrypt0Builder::new().protected(protected_header);
        let cose_encrypt0 = encrypt_cose(encrypt0_builder, wrapping_key);
        Ok(WrappedPrivateKey { cose_encrypt0 })
    }

    /// Unseals a private key from the envelope and stores it in the key store context.
    pub fn unseal<Ids: KeyIds>(
        &self,
        wrapping_key: Ids::Symmetric,
        namespace: PrivateKeyNamespace,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Private, KeyProtectedKeyEnvelopeError> {
        let wrapping_key_ref = ctx
            .get_symmetric_key(wrapping_key)
            .map_err(|_| KeyProtectedKeyEnvelopeError::KeyMissing)?;

        let key_bytes = unseal_key_internal(&self.cose_encrypt0, wrapping_key, namespace)?;

        let content_format = ContentFormat::try_from(&self.cose_encrypt0.protected.header)
            .map_err(|_| {
                KeyProtectedKeyEnvelopeError::Parsing("Invalid content format".to_string())
            })?;

        if content_format != ContentFormat::CoseKey {
            return Err(KeyProtectedKeyEnvelopeError::WrongKeyType);
        }

        let key = PrivateKey::from_cose(&CoseKeyBytes::from(key_bytes)).map_err(|_| {
            KeyProtectedKeyEnvelopeError::Parsing("Failed to decode private key".to_string())
        })?;

        Ok(ctx.add_local_private_key(key))
    }

    /// Get the key ID of the contained key.
    pub fn contained_key_id(&self) -> Result<Option<KeyId>, KeyProtectedKeyEnvelopeError> {
        extract_contained_key_id(&self.cose_encrypt0.protected.header)
    }

    /// Get the key ID of the wrapping key id.
    pub fn wrapping_key_id(&self) -> Result<Option<KeyId>, KeyProtectedKeyEnvelopeError> {
        extract_wrapping_key_id(&self.cose_encrypt0.protected.header)
    }
}

impl From<&WrappedPrivateKey> for Vec<u8> {
    fn from(val: &WrappedPrivateKey) -> Self {
        val.cose_encrypt0
            .clone()
            .to_vec()
            .expect("Serialization to cose should not fail")
    }
}

impl TryFrom<&Vec<u8>> for WrappedPrivateKey {
    type Error = coset::CoseError;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        let cose_encrypt0 = coset::CoseEncrypt0::from_slice(value)?;
        Ok(WrappedPrivateKey { cose_encrypt0 })
    }
}

impl std::fmt::Debug for WrappedPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WrappedPrivateKey")
            .field("cose_encrypt0", &self.cose_encrypt0)
            .finish()
    }
}

impl FromStr for WrappedPrivateKey {
    type Err = KeyProtectedKeyEnvelopeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = B64::try_from(s).map_err(|_| {
            KeyProtectedKeyEnvelopeError::Parsing(
                "Invalid WrappedPrivateKey Base64 encoding".to_string(),
            )
        })?;
        Self::try_from(&data.into_bytes()).map_err(|_| {
            KeyProtectedKeyEnvelopeError::Parsing("Failed to parse WrappedPrivateKey".to_string())
        })
    }
}

impl From<WrappedPrivateKey> for String {
    fn from(val: WrappedPrivateKey) -> Self {
        let serialized: Vec<u8> = (&val).into();
        B64::from(serialized).to_string()
    }
}

impl<'de> Deserialize<'de> for WrappedPrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new())
    }
}

impl Serialize for WrappedPrivateKey {
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
export type WrappedPrivateKey = Tagged<string, "WrappedPrivateKey">;
"#;

#[cfg(feature = "wasm")]
impl wasm_bindgen::describe::WasmDescribe for WrappedPrivateKey {
    fn describe() {
        <String as wasm_bindgen::describe::WasmDescribe>::describe();
    }
}

#[cfg(feature = "wasm")]
impl FromWasmAbi for WrappedPrivateKey {
    type Abi = <String as FromWasmAbi>::Abi;

    unsafe fn from_abi(abi: Self::Abi) -> Self {
        use wasm_bindgen::UnwrapThrowExt;
        let string = unsafe { String::from_abi(abi) };
        WrappedPrivateKey::from_str(&string).unwrap_throw()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        KeyStore, PublicKeyEncryptionAlgorithm, SymmetricKeyAlgorithm, traits::tests::TestIds,
    };

    #[test]
    fn test_seal_unseal_private() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        let envelope = WrappedPrivateKey::seal(
            key_to_seal,
            wrapping_key,
            KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        let unsealed_key = envelope
            .unseal(
                wrapping_key,
                KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
                &mut ctx,
            )
            .unwrap();

        #[allow(deprecated)]
        let unsealed_key_ref = ctx
            .dangerous_get_private_key(unsealed_key)
            .expect("Key should exist in the key store");

        #[allow(deprecated)]
        let original_key_ref = ctx
            .dangerous_get_private_key(key_to_seal)
            .expect("Key should exist in the key store");

        assert_eq!(
            unsealed_key_ref.to_der().unwrap(),
            original_key_ref.to_der().unwrap()
        );
    }

    #[test]
    fn test_contained_key_id_private() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        let envelope = WrappedPrivateKey::seal(
            key_to_seal,
            wrapping_key,
            KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        #[allow(deprecated)]
        let key_to_seal_ref = ctx
            .dangerous_get_private_key(key_to_seal)
            .expect("Key should exist in the key store");

        let contained_key_id = envelope.contained_key_id().unwrap();

        assert_eq!(Some(key_to_seal_ref.key_id()), contained_key_id);
    }

    #[test]
    fn test_string_serialization() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        let envelope = WrappedPrivateKey::seal(
            key_to_seal,
            wrapping_key,
            KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        let serialized: String = envelope.into();
        let deserialized = WrappedPrivateKey::from_str(&serialized).unwrap();

        let unsealed_key = deserialized
            .unseal(
                wrapping_key,
                KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
                &mut ctx,
            )
            .unwrap();

        #[allow(deprecated)]
        let unsealed_key_ref = ctx
            .dangerous_get_private_key(unsealed_key)
            .expect("Key should exist in the key store");

        #[allow(deprecated)]
        let original_key_ref = ctx
            .dangerous_get_private_key(key_to_seal)
            .expect("Key should exist in the key store");

        assert_eq!(
            unsealed_key_ref.to_der().unwrap(),
            original_key_ref.to_der().unwrap()
        );
    }

    #[test]
    fn test_wrong_key() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let wrong_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        let envelope = WrappedPrivateKey::seal(
            key_to_seal,
            wrapping_key,
            KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        assert!(matches!(
            envelope.unseal(
                wrong_key,
                KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
                &mut ctx
            ),
            Err(KeyProtectedKeyEnvelopeError::WrongKey)
        ));
    }

    #[test]
    fn test_wrong_namespace() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        let envelope = WrappedPrivateKey::seal(
            key_to_seal,
            wrapping_key,
            KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        assert!(matches!(
            envelope.unseal(
                wrapping_key,
                KeyProtectedKeyEnvelopeNamespace::ExampleNamespace2,
                &mut ctx
            ),
            Err(KeyProtectedKeyEnvelopeError::InvalidNamespace)
        ));
    }
}

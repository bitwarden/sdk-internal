//! Key protected key envelope is a cryptographic building block that allows sealing a
//! cryptographic key with another symmetric key from the key store.
//!
//! Unlike the password-protected variant, this uses direct encryption with a symmetric key without
//! any Key Derivation Function (KDF). This is suitable for scenarios where the wrapping key is
//! already a strong cryptographic key.
//!
//! The envelope supports three types of keys:
//! - Symmetric keys (XChaCha20Poly1305, AES-256-CBC-HMAC)
//! - Private keys (RSA-2048 in PKCS8 DER format)
//! - Signing keys (Ed25519 in COSE format)
//!
//! For the consumer, the output is an opaque blob that can be later unsealed with the same
//! wrapping key.
//!
//! Internally, the envelope is a CoseEncrypt0 object. The content format in the protected header
//! indicates which type of key is sealed.

use std::str::FromStr;

use bitwarden_encoding::{B64, FromStrVisitor};
use ciborium::{Value, value::Integer};
use coset::{CborSerializable, CoseError, HeaderBuilder};
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::convert::FromWasmAbi;

use crate::{
    BitwardenLegacyKeyBytes, ContentFormat, CoseKeyBytes, CryptoError, EncodedSymmetricKey, KeyIds,
    KeyStoreContext, PrivateKey, SigningKey, SymmetricCryptoKey,
    cose::{
        CONTAINED_KEY_ID, CoseSerializable, KEY_PROTECTED_KEY_ENVELOPE_NAMESPACE,
        KEY_PROTECTED_KEY_TYPE, KEY_PROTECTED_KEY_TYPE_PRIVATE, KEY_PROTECTED_KEY_TYPE_SIGNING,
        KEY_PROTECTED_KEY_TYPE_SYMMETRIC, extract_bytes,
    },
    keys::{KEY_ID_SIZE, KeyId},
    xchacha20,
};

use super::KeyProtectedKeyEnvelopeNamespace;

/// A key-protected key envelope can seal a cryptographic key and protect it with a symmetric key
/// from the key store. This does not use a Key Derivation Function (KDF), and is suitable for
/// scenarios where the wrapping key is already a strong cryptographic key.
///
/// The envelope supports three types of keys: symmetric keys, private keys, and signing keys.
/// Each type has its own seal/unseal methods.
///
/// Internally, XChaCha20-Poly1305 is used to encrypt the key.
pub struct KeyProtectedKeyEnvelope {
    cose_encrypt0: coset::CoseEncrypt0,
}

/// Identifies the type of key contained within a `KeyProtectedKeyEnvelope`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyProtectedEnvelopeType {
    /// A symmetric key is contained in the envelope.
    Symmetric,
    /// A private key is contained in the envelope.
    Private,
    /// A signing key is contained in the envelope.
    Signing,
}

impl KeyProtectedEnvelopeType {
    fn as_label(self) -> i128 {
        match self {
            KeyProtectedEnvelopeType::Symmetric => KEY_PROTECTED_KEY_TYPE_SYMMETRIC,
            KeyProtectedEnvelopeType::Private => KEY_PROTECTED_KEY_TYPE_PRIVATE,
            KeyProtectedEnvelopeType::Signing => KEY_PROTECTED_KEY_TYPE_SIGNING,
        }
    }

    fn try_from_label(label: i128) -> Option<Self> {
        match label {
            KEY_PROTECTED_KEY_TYPE_SYMMETRIC => Some(KeyProtectedEnvelopeType::Symmetric),
            KEY_PROTECTED_KEY_TYPE_PRIVATE => Some(KeyProtectedEnvelopeType::Private),
            KEY_PROTECTED_KEY_TYPE_SIGNING => Some(KeyProtectedEnvelopeType::Signing),
            _ => None,
        }
    }
}

impl KeyProtectedKeyEnvelope {
    /// Seals a symmetric key with another symmetric key from the key store.
    ///
    /// This should never fail, except for memory allocation errors.
    pub fn seal_symmetric<Ids: KeyIds>(
        key_to_seal: Ids::Symmetric,
        wrapping_key: Ids::Symmetric,
        namespace: KeyProtectedKeyEnvelopeNamespace,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<Self, KeyProtectedKeyEnvelopeError> {
        #[allow(deprecated)]
        let key_to_seal_ref = ctx
            .dangerous_get_symmetric_key(key_to_seal)
            .map_err(|_| KeyProtectedKeyEnvelopeError::KeyMissing)?;

        #[allow(deprecated)]
        let wrapping_key_ref = ctx
            .dangerous_get_symmetric_key(wrapping_key)
            .map_err(|_| KeyProtectedKeyEnvelopeError::KeyMissing)?;

        Self::seal_symmetric_ref(key_to_seal_ref, wrapping_key_ref, namespace)
    }

    fn seal_symmetric_ref(
        key_to_seal: &SymmetricCryptoKey,
        wrapping_key: &SymmetricCryptoKey,
        namespace: KeyProtectedKeyEnvelopeNamespace,
    ) -> Result<Self, KeyProtectedKeyEnvelopeError> {
        let (content_format, key_to_seal_bytes) = match key_to_seal.to_encoded_raw() {
            EncodedSymmetricKey::BitwardenLegacyKey(key_bytes) => {
                (ContentFormat::BitwardenLegacyKey, key_bytes.to_vec())
            }
            EncodedSymmetricKey::CoseKey(key_bytes) => (ContentFormat::CoseKey, key_bytes.to_vec()),
        };

        let key_id = key_to_seal.key_id();
        Self::seal_ref_internal(
            &key_to_seal_bytes,
            content_format,
            wrapping_key,
            KeyProtectedEnvelopeType::Symmetric,
            namespace,
            key_id,
        )
    }

    /// Unseals a symmetric key from the key-protected envelope and stores it in the key store
    /// context.
    pub fn unseal_symmetric<Ids: KeyIds>(
        &self,
        wrapping_key: Ids::Symmetric,
        namespace: KeyProtectedKeyEnvelopeNamespace,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Symmetric, KeyProtectedKeyEnvelopeError> {
        #[allow(deprecated)]
        let wrapping_key_ref = ctx
            .dangerous_get_symmetric_key(wrapping_key)
            .map_err(|_| KeyProtectedKeyEnvelopeError::KeyMissing)?;

        let key = self.unseal_symmetric_ref(wrapping_key_ref, namespace)?;
        Ok(ctx.add_local_symmetric_key(key))
    }

    fn unseal_symmetric_ref(
        &self,
        wrapping_key: &SymmetricCryptoKey,
        namespace: KeyProtectedKeyEnvelopeNamespace,
    ) -> Result<SymmetricCryptoKey, KeyProtectedKeyEnvelopeError> {
        let (key_bytes, content_format, envelope_type) =
            self.unseal_ref_internal(wrapping_key, namespace)?;

        if envelope_type != KeyProtectedEnvelopeType::Symmetric {
            return Err(KeyProtectedKeyEnvelopeError::WrongKeyType);
        }

        let encoded_key = match content_format {
            ContentFormat::BitwardenLegacyKey => {
                EncodedSymmetricKey::BitwardenLegacyKey(BitwardenLegacyKeyBytes::from(key_bytes))
            }
            ContentFormat::CoseKey => EncodedSymmetricKey::CoseKey(CoseKeyBytes::from(key_bytes)),
            _ => {
                return Err(KeyProtectedKeyEnvelopeError::WrongKeyType);
            }
        };

        SymmetricCryptoKey::try_from(encoded_key)
            .map_err(|_| KeyProtectedKeyEnvelopeError::WrongKeyType)
    }

    /// Seals a private key with a symmetric key from the key store.
    ///
    /// This should never fail, except for memory allocation errors.
    pub fn seal_private<Ids: KeyIds>(
        key_to_seal: Ids::Private,
        wrapping_key: Ids::Symmetric,
        namespace: KeyProtectedKeyEnvelopeNamespace,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<Self, KeyProtectedKeyEnvelopeError> {
        #[allow(deprecated)]
        let key_to_seal_ref = ctx
            .dangerous_get_private_key(key_to_seal)
            .map_err(|_| KeyProtectedKeyEnvelopeError::KeyMissing)?;

        #[allow(deprecated)]
        let wrapping_key_ref = ctx
            .dangerous_get_symmetric_key(wrapping_key)
            .map_err(|_| KeyProtectedKeyEnvelopeError::KeyMissing)?;

        Self::seal_private_ref(key_to_seal_ref, wrapping_key_ref, namespace)
    }

    fn seal_private_ref(
        key_to_seal: &PrivateKey,
        wrapping_key: &SymmetricCryptoKey,
        namespace: KeyProtectedKeyEnvelopeNamespace,
    ) -> Result<Self, KeyProtectedKeyEnvelopeError> {
        let key_to_seal_bytes = key_to_seal.to_cose();
        Self::seal_ref_internal(
            key_to_seal_bytes.as_ref(),
            ContentFormat::CoseKey,
            wrapping_key,
            KeyProtectedEnvelopeType::Private,
            namespace,
            Some(key_to_seal.key_id()),
        )
    }

    /// Unseals a private key from the key-protected envelope and stores it in the key store
    /// context.
    pub fn unseal_private<Ids: KeyIds>(
        &self,
        wrapping_key: Ids::Symmetric,
        namespace: KeyProtectedKeyEnvelopeNamespace,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Private, KeyProtectedKeyEnvelopeError> {
        #[allow(deprecated)]
        let wrapping_key_ref = ctx
            .dangerous_get_symmetric_key(wrapping_key)
            .map_err(|_| KeyProtectedKeyEnvelopeError::KeyMissing)?;

        let key = self.unseal_private_ref(wrapping_key_ref, namespace)?;
        Ok(ctx.add_local_private_key(key))
    }

    fn unseal_private_ref(
        &self,
        wrapping_key: &SymmetricCryptoKey,
        namespace: KeyProtectedKeyEnvelopeNamespace,
    ) -> Result<PrivateKey, KeyProtectedKeyEnvelopeError> {
        let (key_bytes, content_format, envelope_type) =
            self.unseal_ref_internal(wrapping_key, namespace)?;

        if envelope_type != KeyProtectedEnvelopeType::Private {
            return Err(KeyProtectedKeyEnvelopeError::WrongKeyType);
        }

        if content_format != ContentFormat::CoseKey {
            return Err(KeyProtectedKeyEnvelopeError::WrongKeyType);
        }

        PrivateKey::from_cose(&CoseKeyBytes::from(key_bytes)).map_err(|_| {
            KeyProtectedKeyEnvelopeError::Parsing("Failed to decode private key".to_string())
        })
    }

    /// Seals a signing key with a symmetric key from the key store.
    ///
    /// This should never fail, except for memory allocation errors.
    pub fn seal_signing<Ids: KeyIds>(
        key_to_seal: Ids::Signing,
        wrapping_key: Ids::Symmetric,
        namespace: KeyProtectedKeyEnvelopeNamespace,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<Self, KeyProtectedKeyEnvelopeError> {
        #[allow(deprecated)]
        let key_to_seal_ref = ctx
            .dangerous_get_signing_key(key_to_seal)
            .map_err(|_| KeyProtectedKeyEnvelopeError::KeyMissing)?;

        #[allow(deprecated)]
        let wrapping_key_ref = ctx
            .dangerous_get_symmetric_key(wrapping_key)
            .map_err(|_| KeyProtectedKeyEnvelopeError::KeyMissing)?;

        Self::seal_signing_ref(key_to_seal_ref, wrapping_key_ref, namespace)
    }

    fn seal_signing_ref(
        key_to_seal: &SigningKey,
        wrapping_key: &SymmetricCryptoKey,
        namespace: KeyProtectedKeyEnvelopeNamespace,
    ) -> Result<Self, KeyProtectedKeyEnvelopeError> {
        let key_to_seal_bytes = key_to_seal.to_cose();
        Self::seal_ref_internal(
            key_to_seal_bytes.as_ref(),
            ContentFormat::CoseKey,
            wrapping_key,
            KeyProtectedEnvelopeType::Signing,
            namespace,
            Some(key_to_seal.key_id()),
        )
    }

    /// Unseals a signing key from the key-protected envelope and stores it in the key store
    /// context.
    pub fn unseal_signing<Ids: KeyIds>(
        &self,
        wrapping_key: Ids::Symmetric,
        namespace: KeyProtectedKeyEnvelopeNamespace,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Signing, KeyProtectedKeyEnvelopeError> {
        #[allow(deprecated)]
        let wrapping_key_ref = ctx
            .dangerous_get_symmetric_key(wrapping_key)
            .map_err(|_| KeyProtectedKeyEnvelopeError::KeyMissing)?;

        let key = self.unseal_signing_ref(wrapping_key_ref, namespace)?;
        Ok(ctx.add_local_signing_key(key))
    }

    fn unseal_signing_ref(
        &self,
        wrapping_key: &SymmetricCryptoKey,
        namespace: KeyProtectedKeyEnvelopeNamespace,
    ) -> Result<SigningKey, KeyProtectedKeyEnvelopeError> {
        let (key_bytes, content_format, envelope_type) =
            self.unseal_ref_internal(wrapping_key, namespace)?;

        if envelope_type != KeyProtectedEnvelopeType::Signing {
            return Err(KeyProtectedKeyEnvelopeError::WrongKeyType);
        }

        if content_format != ContentFormat::CoseKey {
            return Err(KeyProtectedKeyEnvelopeError::WrongKeyType);
        }

        SigningKey::from_cose(&CoseKeyBytes::from(key_bytes)).map_err(|_| {
            KeyProtectedKeyEnvelopeError::Parsing("Failed to decode signing key".to_string())
        })
    }

    /// Internal helper to seal a key with a wrapping key.
    fn seal_ref_internal(
        key_to_seal_bytes: &[u8],
        content_format: ContentFormat,
        wrapping_key: &SymmetricCryptoKey,
        envelope_type: KeyProtectedEnvelopeType,
        namespace: KeyProtectedKeyEnvelopeNamespace,
        contained_key_id: Option<KeyId>,
    ) -> Result<Self, KeyProtectedKeyEnvelopeError> {
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
                Value::Integer(Integer::from(envelope_type.as_label() as i64)),
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

        Ok(KeyProtectedKeyEnvelope { cose_encrypt0 })
    }

    /// Internal helper to unseal a key with a wrapping key.
    fn unseal_ref_internal(
        &self,
        wrapping_key: &SymmetricCryptoKey,
        expected_namespace: KeyProtectedKeyEnvelopeNamespace,
    ) -> Result<(Vec<u8>, ContentFormat, KeyProtectedEnvelopeType), KeyProtectedKeyEnvelopeError>
    {
        // Extract the XChaCha20Poly1305 key from the wrapping key
        let wrapping_key_inner = match wrapping_key {
            SymmetricCryptoKey::XChaCha20Poly1305Key(key) => key,
            _ => {
                return Err(KeyProtectedKeyEnvelopeError::Parsing(
                    "Wrapping key must be XChaCha20Poly1305".to_string(),
                ));
            }
        };

        let nonce: [u8; xchacha20::NONCE_SIZE] = self
            .cose_encrypt0
            .unprotected
            .iv
            .clone()
            .try_into()
            .map_err(|_| KeyProtectedKeyEnvelopeError::Parsing("Invalid IV".to_string()))?;

        let content_format = ContentFormat::try_from(&self.cose_encrypt0.protected.header)
            .map_err(|_| {
                KeyProtectedKeyEnvelopeError::Parsing("Invalid content format".to_string())
            })?;

        let envelope_type = self.key_type().map_err(|_| {
            KeyProtectedKeyEnvelopeError::Parsing("Invalid envelope type".to_string())
        })?;

        // Extract and validate namespace
        let envelope_namespace = self.extract_namespace()?;
        if envelope_namespace != expected_namespace {
            return Err(KeyProtectedKeyEnvelopeError::InvalidNamespace);
        }

        let key_bytes = self
            .cose_encrypt0
            .decrypt_ciphertext(
                &[],
                || CryptoError::MissingField("ciphertext"),
                |data, aad| {
                    xchacha20::decrypt_xchacha20_poly1305(
                        &nonce,
                        &(*wrapping_key_inner.enc_key).into(),
                        data,
                        aad,
                    )
                },
            )
            .map_err(|_| KeyProtectedKeyEnvelopeError::WrongKey)?;

        Ok((key_bytes, content_format, envelope_type))
    }
}

impl From<&KeyProtectedKeyEnvelope> for Vec<u8> {
    fn from(val: &KeyProtectedKeyEnvelope) -> Self {
        val.cose_encrypt0
            .clone()
            .to_vec()
            .expect("Serialization to cose should not fail")
    }
}

impl TryFrom<&Vec<u8>> for KeyProtectedKeyEnvelope {
    type Error = CoseError;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        let cose_encrypt0 = coset::CoseEncrypt0::from_slice(value)?;
        Ok(KeyProtectedKeyEnvelope { cose_encrypt0 })
    }
}

impl KeyProtectedKeyEnvelope {
    /// Returns the type of key contained inside the envelope (symmetric, private, signing).
    pub fn key_type(&self) -> Result<KeyProtectedEnvelopeType, KeyProtectedKeyEnvelopeError> {
        self.cose_encrypt0
            .protected
            .header
            .rest
            .iter()
            .find_map(|(label, value)| match (label, value) {
                (coset::Label::Int(key), Value::Integer(int)) if *key == KEY_PROTECTED_KEY_TYPE => {
                    let decoded: i128 = (*int).into();
                    KeyProtectedEnvelopeType::try_from_label(decoded).map(Ok)
                }
                _ => None,
            })
            .unwrap_or_else(|| {
                Err(KeyProtectedKeyEnvelopeError::Parsing(
                    "Missing or invalid envelope type".to_string(),
                ))
            })
    }

    /// Returns the namespace of the key protected key envelope.
    fn extract_namespace(
        &self,
    ) -> Result<KeyProtectedKeyEnvelopeNamespace, KeyProtectedKeyEnvelopeError> {
        self.cose_encrypt0
            .protected
            .header
            .rest
            .iter()
            .find_map(|(label, value)| match (label, value) {
                (coset::Label::Int(key), Value::Integer(int))
                    if *key == KEY_PROTECTED_KEY_ENVELOPE_NAMESPACE =>
                {
                    let decoded: i128 = (*int).into();
                    Some(KeyProtectedKeyEnvelopeNamespace::try_from(decoded))
                }
                _ => None,
            })
            .unwrap_or_else(|| Err(KeyProtectedKeyEnvelopeError::InvalidNamespace))
    }

    /// Get the key ID of the contained key, if the key ID is stored on the envelope headers.
    /// Only COSE keys have a key ID, legacy keys do not.
    pub fn contained_key_id(&self) -> Result<Option<KeyId>, KeyProtectedKeyEnvelopeError> {
        let key_id_bytes = extract_bytes(
            &self.cose_encrypt0.protected.header,
            CONTAINED_KEY_ID,
            "key id",
        );

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
}

impl std::fmt::Debug for KeyProtectedKeyEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyProtectedKeyEnvelope")
            .field("cose_encrypt0", &self.cose_encrypt0)
            .finish()
    }
}

impl FromStr for KeyProtectedKeyEnvelope {
    type Err = KeyProtectedKeyEnvelopeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = B64::try_from(s).map_err(|_| {
            KeyProtectedKeyEnvelopeError::Parsing(
                "Invalid KeyProtectedKeyEnvelope Base64 encoding".to_string(),
            )
        })?;
        Self::try_from(&data.into_bytes()).map_err(|_| {
            KeyProtectedKeyEnvelopeError::Parsing(
                "Failed to parse KeyProtectedKeyEnvelope".to_string(),
            )
        })
    }
}

impl From<KeyProtectedKeyEnvelope> for String {
    fn from(val: KeyProtectedKeyEnvelope) -> Self {
        let serialized: Vec<u8> = (&val).into();
        B64::from(serialized).to_string()
    }
}

impl<'de> Deserialize<'de> for KeyProtectedKeyEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new())
    }
}

impl Serialize for KeyProtectedKeyEnvelope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let serialized: Vec<u8> = self.into();
        serializer.serialize_str(&B64::from(serialized).to_string())
    }
}

/// Errors that can occur when sealing or unsealing a key with the `KeyProtectedKeyEnvelope`.
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

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export type KeyProtectedKeyEnvelope = Tagged<string, "KeyProtectedKeyEnvelope">;
"#;

#[cfg(feature = "wasm")]
impl wasm_bindgen::describe::WasmDescribe for KeyProtectedKeyEnvelope {
    fn describe() {
        <String as wasm_bindgen::describe::WasmDescribe>::describe();
    }
}

#[cfg(feature = "wasm")]
impl FromWasmAbi for KeyProtectedKeyEnvelope {
    type Abi = <String as FromWasmAbi>::Abi;

    unsafe fn from_abi(abi: Self::Abi) -> Self {
        use wasm_bindgen::UnwrapThrowExt;
        let string = unsafe { String::from_abi(abi) };
        KeyProtectedKeyEnvelope::from_str(&string).unwrap_throw()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        KeyStore, PublicKeyEncryptionAlgorithm, SignatureAlgorithm, SymmetricKeyAlgorithm,
        traits::tests::TestIds,
    };

    #[test]
    fn test_seal_unseal_symmetric_cosekey() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        // Seal the key
        let envelope = KeyProtectedKeyEnvelope::seal_symmetric(
            key_to_seal,
            wrapping_key,
            KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        assert_eq!(
            envelope.key_type().unwrap(),
            KeyProtectedEnvelopeType::Symmetric
        );

        // Serialize and deserialize
        let serialized: Vec<u8> = (&envelope).into();
        let deserialized = KeyProtectedKeyEnvelope::try_from(&serialized).unwrap();

        // Unseal the key
        let unsealed_key = deserialized
            .unseal_symmetric(
                wrapping_key,
                KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
                &mut ctx,
            )
            .unwrap();

        // Verify that the unsealed key matches the original key
        #[allow(deprecated)]
        let unsealed_key_ref = ctx
            .dangerous_get_symmetric_key(unsealed_key)
            .expect("Key should exist in the key store");

        #[allow(deprecated)]
        let original_key_ref = ctx
            .dangerous_get_symmetric_key(key_to_seal)
            .expect("Key should exist in the key store");

        assert_eq!(unsealed_key_ref, original_key_ref);
    }

    #[test]
    fn test_contained_key_id_symmetric_cosekey() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        let envelope = KeyProtectedKeyEnvelope::seal_symmetric(
            key_to_seal,
            wrapping_key,
            KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        #[allow(deprecated)]
        let key_to_seal_ref = ctx
            .dangerous_get_symmetric_key(key_to_seal)
            .expect("Key should exist in the key store");

        let expected_key_id = key_to_seal_ref
            .key_id()
            .expect("COSE symmetric keys always have a key id");

        let contained_key_id = envelope.contained_key_id().unwrap();

        assert_eq!(Some(expected_key_id), contained_key_id);
    }

    #[test]
    fn test_seal_unseal_symmetric_legacy() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.generate_symmetric_key();
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        // Seal the key
        let envelope = KeyProtectedKeyEnvelope::seal_symmetric(
            key_to_seal,
            wrapping_key,
            KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        assert_eq!(
            envelope.key_type().unwrap(),
            KeyProtectedEnvelopeType::Symmetric
        );

        // Unseal the key
        let unsealed_key = envelope
            .unseal_symmetric(
                wrapping_key,
                KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
                &mut ctx,
            )
            .unwrap();

        // Verify that the unsealed key matches the original key
        #[allow(deprecated)]
        let unsealed_key_ref = ctx
            .dangerous_get_symmetric_key(unsealed_key)
            .expect("Key should exist in the key store");

        #[allow(deprecated)]
        let original_key_ref = ctx
            .dangerous_get_symmetric_key(key_to_seal)
            .expect("Key should exist in the key store");

        assert_eq!(unsealed_key_ref, original_key_ref);
    }

    #[test]
    fn test_contained_key_id_symmetric_legacy() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.generate_symmetric_key();
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        let envelope = KeyProtectedKeyEnvelope::seal_symmetric(
            key_to_seal,
            wrapping_key,
            KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        let contained_key_id = envelope.contained_key_id().unwrap();

        assert_eq!(None, contained_key_id);
    }

    #[test]
    fn test_seal_unseal_private() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        // Seal the key
        let envelope = KeyProtectedKeyEnvelope::seal_private(
            key_to_seal,
            wrapping_key,
            KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        assert_eq!(
            envelope.key_type().unwrap(),
            KeyProtectedEnvelopeType::Private
        );

        // Unseal the key
        let unsealed_key = envelope
            .unseal_private(
                wrapping_key,
                KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
                &mut ctx,
            )
            .unwrap();

        // Verify that the unsealed key matches the original key by comparing DER encoding
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

        let envelope = KeyProtectedKeyEnvelope::seal_private(
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
    fn test_seal_unseal_signing() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_signing_key(SignatureAlgorithm::Ed25519);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        // Seal the key
        let envelope = KeyProtectedKeyEnvelope::seal_signing(
            key_to_seal,
            wrapping_key,
            KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        assert_eq!(
            envelope.key_type().unwrap(),
            KeyProtectedEnvelopeType::Signing
        );

        // Unseal the key
        let unsealed_key = envelope
            .unseal_signing(
                wrapping_key,
                KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
                &mut ctx,
            )
            .unwrap();

        // Verify that the unsealed key matches the original key by comparing COSE encoding
        #[allow(deprecated)]
        let unsealed_key_ref = ctx.dangerous_get_signing_key(unsealed_key).unwrap();

        #[allow(deprecated)]
        let original_key_ref = ctx.dangerous_get_signing_key(key_to_seal).unwrap();

        assert_eq!(unsealed_key_ref.to_cose(), original_key_ref.to_cose());
    }

    #[test]
    fn test_contained_key_id_signing() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_signing_key(SignatureAlgorithm::Ed25519);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        let envelope = KeyProtectedKeyEnvelope::seal_signing(
            key_to_seal,
            wrapping_key,
            KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        #[allow(deprecated)]
        let key_to_seal_ref = ctx
            .dangerous_get_signing_key(key_to_seal)
            .expect("Key should exist in the key store");

        let contained_key_id = envelope.contained_key_id().unwrap();

        assert_eq!(Some(key_to_seal_ref.key_id()), contained_key_id);
    }

    #[test]
    fn test_wrong_key() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let wrong_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        // Seal the key
        let envelope = KeyProtectedKeyEnvelope::seal_symmetric(
            key_to_seal,
            wrapping_key,
            KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        // Attempt to unseal with the wrong key
        assert!(matches!(
            envelope.unseal_symmetric(
                wrong_key,
                KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
                &mut ctx
            ),
            Err(KeyProtectedKeyEnvelopeError::WrongKey)
        ));
    }

    #[test]
    fn test_wrong_key_type_symmetric_as_private() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        // Seal a symmetric key
        let envelope = KeyProtectedKeyEnvelope::seal_symmetric(
            key_to_seal,
            wrapping_key,
            KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        // Attempt to unseal as private key
        assert!(matches!(
            envelope.unseal_private(
                wrapping_key,
                KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
                &mut ctx
            ),
            Err(KeyProtectedKeyEnvelopeError::WrongKeyType)
        ));
    }

    #[test]
    fn test_wrong_key_type_private_as_symmetric() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        // Seal a private key
        let envelope = KeyProtectedKeyEnvelope::seal_private(
            key_to_seal,
            wrapping_key,
            KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        // Attempt to unseal as symmetric key
        assert!(matches!(
            envelope.unseal_symmetric(
                wrapping_key,
                KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
                &mut ctx
            ),
            Err(KeyProtectedKeyEnvelopeError::WrongKeyType)
        ));
    }

    #[test]
    fn test_wrong_key_type_signing_as_symmetric() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_signing_key(SignatureAlgorithm::Ed25519);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        // Seal a signing key
        let envelope = KeyProtectedKeyEnvelope::seal_signing(
            key_to_seal,
            wrapping_key,
            KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        // Attempt to unseal as symmetric key
        assert!(matches!(
            envelope.unseal_symmetric(
                wrapping_key,
                KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
                &mut ctx
            ),
            Err(KeyProtectedKeyEnvelopeError::WrongKeyType)
        ));
    }

    #[test]
    fn test_string_serialization() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        // Seal the key
        let envelope = KeyProtectedKeyEnvelope::seal_symmetric(
            key_to_seal,
            wrapping_key,
            KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        // Serialize to string
        let serialized: String = envelope.into();

        // Deserialize from string
        let deserialized = KeyProtectedKeyEnvelope::from_str(&serialized).unwrap();

        // Unseal and verify
        let unsealed_key = deserialized
            .unseal_symmetric(
                wrapping_key,
                KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
                &mut ctx,
            )
            .unwrap();

        #[allow(deprecated)]
        let unsealed_key_ref = ctx
            .dangerous_get_symmetric_key(unsealed_key)
            .expect("Key should exist in the key store");

        #[allow(deprecated)]
        let original_key_ref = ctx
            .dangerous_get_symmetric_key(key_to_seal)
            .expect("Key should exist in the key store");

        assert_eq!(unsealed_key_ref, original_key_ref);
    }

    #[test]
    fn test_wrong_namespace_symmetric() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        // Seal with ExampleNamespace
        let envelope = KeyProtectedKeyEnvelope::seal_symmetric(
            key_to_seal,
            wrapping_key,
            KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        // Attempt to unseal with ExampleNamespace2
        assert!(matches!(
            envelope.unseal_symmetric(
                wrapping_key,
                KeyProtectedKeyEnvelopeNamespace::ExampleNamespace2,
                &mut ctx
            ),
            Err(KeyProtectedKeyEnvelopeError::InvalidNamespace)
        ));
    }

    #[test]
    fn test_wrong_namespace_private() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        // Seal with ExampleNamespace
        let envelope = KeyProtectedKeyEnvelope::seal_private(
            key_to_seal,
            wrapping_key,
            KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        // Attempt to unseal with ExampleNamespace2
        assert!(matches!(
            envelope.unseal_private(
                wrapping_key,
                KeyProtectedKeyEnvelopeNamespace::ExampleNamespace2,
                &mut ctx
            ),
            Err(KeyProtectedKeyEnvelopeError::InvalidNamespace)
        ));
    }

    #[test]
    fn test_wrong_namespace_signing() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_signing_key(SignatureAlgorithm::Ed25519);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        // Seal with ExampleNamespace
        let envelope = KeyProtectedKeyEnvelope::seal_signing(
            key_to_seal,
            wrapping_key,
            KeyProtectedKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        // Attempt to unseal with ExampleNamespace2
        assert!(matches!(
            envelope.unseal_signing(
                wrapping_key,
                KeyProtectedKeyEnvelopeNamespace::ExampleNamespace2,
                &mut ctx
            ),
            Err(KeyProtectedKeyEnvelopeError::InvalidNamespace)
        ));
    }
}

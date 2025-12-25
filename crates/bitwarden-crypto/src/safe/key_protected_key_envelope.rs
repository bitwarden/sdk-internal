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
use coset::{CborSerializable, CoseError, HeaderBuilder};
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::convert::FromWasmAbi;

use crate::{
    AsymmetricCryptoKey, BitwardenLegacyKeyBytes, ContentFormat, CoseKeyBytes, CryptoError,
    EncodedSymmetricKey, KeyIds, KeyStoreContext, Pkcs8PrivateKeyBytes, SigningKey,
    SymmetricCryptoKey,
    cose::CoseSerializable,
    xchacha20,
};

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

impl KeyProtectedKeyEnvelope {
    /// Seals a symmetric key with another symmetric key from the key store.
    ///
    /// This should never fail, except for memory allocation errors.
    pub fn seal_symmetric<Ids: KeyIds>(
        key_to_seal: Ids::Symmetric,
        wrapping_key: Ids::Symmetric,
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

        Self::seal_symmetric_ref(key_to_seal_ref, wrapping_key_ref)
    }

    fn seal_symmetric_ref(
        key_to_seal: &SymmetricCryptoKey,
        wrapping_key: &SymmetricCryptoKey,
    ) -> Result<Self, KeyProtectedKeyEnvelopeError> {
        let (content_format, key_to_seal_bytes) = match key_to_seal.to_encoded_raw() {
            EncodedSymmetricKey::BitwardenLegacyKey(key_bytes) => {
                (ContentFormat::BitwardenLegacyKey, key_bytes.to_vec())
            }
            EncodedSymmetricKey::CoseKey(key_bytes) => (ContentFormat::CoseKey, key_bytes.to_vec()),
        };

        Self::seal_ref_internal(&key_to_seal_bytes, content_format, wrapping_key)
    }

    /// Unseals a symmetric key from the key-protected envelope and stores it in the key store
    /// context.
    pub fn unseal_symmetric<Ids: KeyIds>(
        &self,
        wrapping_key: Ids::Symmetric,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Symmetric, KeyProtectedKeyEnvelopeError> {
        #[allow(deprecated)]
        let wrapping_key_ref = ctx
            .dangerous_get_symmetric_key(wrapping_key)
            .map_err(|_| KeyProtectedKeyEnvelopeError::KeyMissing)?;

        let key = self.unseal_symmetric_ref(wrapping_key_ref)?;
        Ok(ctx.add_local_symmetric_key(key))
    }

    fn unseal_symmetric_ref(
        &self,
        wrapping_key: &SymmetricCryptoKey,
    ) -> Result<SymmetricCryptoKey, KeyProtectedKeyEnvelopeError> {
        let (key_bytes, content_format) = self.unseal_ref_internal(wrapping_key)?;

        let encoded_key = match content_format {
            ContentFormat::BitwardenLegacyKey => {
                EncodedSymmetricKey::BitwardenLegacyKey(BitwardenLegacyKeyBytes::from(key_bytes))
            }
            ContentFormat::CoseKey => EncodedSymmetricKey::CoseKey(CoseKeyBytes::from(key_bytes)),
            _ => {
                return Err(KeyProtectedKeyEnvelopeError::WrongKeyType);
            }
        };

        SymmetricCryptoKey::try_from(encoded_key).map_err(|_| {
            KeyProtectedKeyEnvelopeError::WrongKeyType
        })
    }

    /// Seals a private key with a symmetric key from the key store.
    ///
    /// This should never fail, except for memory allocation errors.
    pub fn seal_private<Ids: KeyIds>(
        key_to_seal: Ids::Asymmetric,
        wrapping_key: Ids::Symmetric,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<Self, KeyProtectedKeyEnvelopeError> {
        #[allow(deprecated)]
        let key_to_seal_ref = ctx
            .dangerous_get_asymmetric_key(key_to_seal)
            .map_err(|_| KeyProtectedKeyEnvelopeError::KeyMissing)?;

        #[allow(deprecated)]
        let wrapping_key_ref = ctx
            .dangerous_get_symmetric_key(wrapping_key)
            .map_err(|_| KeyProtectedKeyEnvelopeError::KeyMissing)?;

        Self::seal_private_ref(key_to_seal_ref, wrapping_key_ref)
    }

    fn seal_private_ref(
        key_to_seal: &AsymmetricCryptoKey,
        wrapping_key: &SymmetricCryptoKey,
    ) -> Result<Self, KeyProtectedKeyEnvelopeError> {
        let key_to_seal_bytes = key_to_seal
            .to_der()
            .map_err(|_| KeyProtectedKeyEnvelopeError::Parsing("Failed to encode private key".to_string()))?;

        Self::seal_ref_internal(
            key_to_seal_bytes.as_ref(),
            ContentFormat::Pkcs8PrivateKey,
            wrapping_key,
        )
    }

    /// Unseals a private key from the key-protected envelope and stores it in the key store
    /// context.
    pub fn unseal_private<Ids: KeyIds>(
        &self,
        wrapping_key: Ids::Symmetric,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Asymmetric, KeyProtectedKeyEnvelopeError> {
        #[allow(deprecated)]
        let wrapping_key_ref = ctx
            .dangerous_get_symmetric_key(wrapping_key)
            .map_err(|_| KeyProtectedKeyEnvelopeError::KeyMissing)?;

        let key = self.unseal_private_ref(wrapping_key_ref)?;
        ctx.add_local_asymmetric_key(key)
            .map_err(|_| KeyProtectedKeyEnvelopeError::KeyStore)
    }

    fn unseal_private_ref(
        &self,
        wrapping_key: &SymmetricCryptoKey,
    ) -> Result<AsymmetricCryptoKey, KeyProtectedKeyEnvelopeError> {
        let (key_bytes, content_format) = self.unseal_ref_internal(wrapping_key)?;

        if content_format != ContentFormat::Pkcs8PrivateKey {
            return Err(KeyProtectedKeyEnvelopeError::WrongKeyType);
        }

        AsymmetricCryptoKey::from_der(&Pkcs8PrivateKeyBytes::from(key_bytes)).map_err(|_| {
            KeyProtectedKeyEnvelopeError::Parsing("Failed to decode private key".to_string())
        })
    }

    /// Seals a signing key with a symmetric key from the key store.
    ///
    /// This should never fail, except for memory allocation errors.
    pub fn seal_signing<Ids: KeyIds>(
        key_to_seal: Ids::Signing,
        wrapping_key: Ids::Symmetric,
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

        Self::seal_signing_ref(key_to_seal_ref, wrapping_key_ref)
    }

    fn seal_signing_ref(
        key_to_seal: &SigningKey,
        wrapping_key: &SymmetricCryptoKey,
    ) -> Result<Self, KeyProtectedKeyEnvelopeError> {
        let key_to_seal_bytes = key_to_seal.to_cose();

        Self::seal_ref_internal(key_to_seal_bytes.as_ref(), ContentFormat::CoseKey, wrapping_key)
    }

    /// Unseals a signing key from the key-protected envelope and stores it in the key store
    /// context.
    pub fn unseal_signing<Ids: KeyIds>(
        &self,
        wrapping_key: Ids::Symmetric,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Signing, KeyProtectedKeyEnvelopeError> {
        #[allow(deprecated)]
        let wrapping_key_ref = ctx
            .dangerous_get_symmetric_key(wrapping_key)
            .map_err(|_| KeyProtectedKeyEnvelopeError::KeyMissing)?;

        let key = self.unseal_signing_ref(wrapping_key_ref)?;
        ctx.add_local_signing_key(key)
            .map_err(|_| KeyProtectedKeyEnvelopeError::KeyStore)
    }

    fn unseal_signing_ref(
        &self,
        wrapping_key: &SymmetricCryptoKey,
    ) -> Result<SigningKey, KeyProtectedKeyEnvelopeError> {
        let (key_bytes, content_format) = self.unseal_ref_internal(wrapping_key)?;

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
    ) -> Result<Self, KeyProtectedKeyEnvelopeError> {
        // Extract the XChaCha20Poly1305 key from the wrapping key
        let wrapping_key_inner = match wrapping_key {
            SymmetricCryptoKey::XChaCha20Poly1305Key(key) => key,
            _ => {
                return Err(KeyProtectedKeyEnvelopeError::Parsing(
                    "Wrapping key must be XChaCha20Poly1305".to_string(),
                ))
            }
        };

        let mut nonce = [0u8; xchacha20::NONCE_SIZE];

        let protected_header = HeaderBuilder::from(content_format).build();

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
    ) -> Result<(Vec<u8>, ContentFormat), KeyProtectedKeyEnvelopeError> {
        // Extract the XChaCha20Poly1305 key from the wrapping key
        let wrapping_key_inner = match wrapping_key {
            SymmetricCryptoKey::XChaCha20Poly1305Key(key) => key,
            _ => {
                return Err(KeyProtectedKeyEnvelopeError::Parsing(
                    "Wrapping key must be XChaCha20Poly1305".to_string(),
                ))
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

        Ok((key_bytes, content_format))
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
        KeyStore, SignatureAlgorithm, SymmetricKeyAlgorithm,
        traits::tests::TestIds,
    };

    #[test]
    fn test_seal_unseal_symmetric_cosekey() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        // Seal the key
        let envelope =
            KeyProtectedKeyEnvelope::seal_symmetric(key_to_seal, wrapping_key, &ctx).unwrap();

        // Serialize and deserialize
        let serialized: Vec<u8> = (&envelope).into();
        let deserialized = KeyProtectedKeyEnvelope::try_from(&serialized).unwrap();

        // Unseal the key
        let unsealed_key = deserialized
            .unseal_symmetric(wrapping_key, &mut ctx)
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
    fn test_seal_unseal_symmetric_legacy() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.generate_symmetric_key();
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        // Seal the key
        let envelope =
            KeyProtectedKeyEnvelope::seal_symmetric(key_to_seal, wrapping_key, &ctx).unwrap();

        // Unseal the key
        let unsealed_key = envelope.unseal_symmetric(wrapping_key, &mut ctx).unwrap();

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
    fn test_seal_unseal_private() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_asymmetric_key().unwrap();
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        // Seal the key
        let envelope =
            KeyProtectedKeyEnvelope::seal_private(key_to_seal, wrapping_key, &ctx).unwrap();

        // Unseal the key
        let unsealed_key = envelope.unseal_private(wrapping_key, &mut ctx).unwrap();

        // Verify that the unsealed key matches the original key by comparing DER encoding
        #[allow(deprecated)]
        let unsealed_key_ref = ctx
            .dangerous_get_asymmetric_key(unsealed_key)
            .expect("Key should exist in the key store");

        #[allow(deprecated)]
        let original_key_ref = ctx
            .dangerous_get_asymmetric_key(key_to_seal)
            .expect("Key should exist in the key store");

        assert_eq!(
            unsealed_key_ref.to_der().unwrap(),
            original_key_ref.to_der().unwrap()
        );
    }

    #[test]
    fn test_seal_unseal_signing() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_signing_key(SignatureAlgorithm::Ed25519).unwrap();
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        // Seal the key
        let envelope =
            KeyProtectedKeyEnvelope::seal_signing(key_to_seal, wrapping_key, &ctx).unwrap();

        // Unseal the key
        let unsealed_key = envelope.unseal_signing(wrapping_key, &mut ctx).unwrap();

        // Verify that the unsealed key matches the original key by comparing COSE encoding
        #[allow(deprecated)]
        let unsealed_key_ref = ctx
            .dangerous_get_signing_key(unsealed_key)
            .expect("Key should exist in the key store");

        #[allow(deprecated)]
        let original_key_ref = ctx
            .dangerous_get_signing_key(key_to_seal)
            .expect("Key should exist in the key store");

        assert_eq!(unsealed_key_ref.to_cose(), original_key_ref.to_cose());
    }

    #[test]
    fn test_wrong_key() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let wrong_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        // Seal the key
        let envelope =
            KeyProtectedKeyEnvelope::seal_symmetric(key_to_seal, wrapping_key, &ctx).unwrap();

        // Attempt to unseal with the wrong key
        assert!(matches!(
            envelope.unseal_symmetric(wrong_key, &mut ctx),
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
        let envelope =
            KeyProtectedKeyEnvelope::seal_symmetric(key_to_seal, wrapping_key, &ctx).unwrap();

        // Attempt to unseal as private key
        assert!(matches!(
            envelope.unseal_private(wrapping_key, &mut ctx),
            Err(KeyProtectedKeyEnvelopeError::WrongKeyType)
        ));
    }

    #[test]
    fn test_wrong_key_type_private_as_symmetric() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_asymmetric_key().unwrap();
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        // Seal a private key
        let envelope =
            KeyProtectedKeyEnvelope::seal_private(key_to_seal, wrapping_key, &ctx).unwrap();

        // Attempt to unseal as symmetric key
        assert!(matches!(
            envelope.unseal_symmetric(wrapping_key, &mut ctx),
            Err(KeyProtectedKeyEnvelopeError::WrongKeyType)
        ));
    }

    #[test]
    fn test_wrong_key_type_signing_as_symmetric() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_signing_key(SignatureAlgorithm::Ed25519).unwrap();
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        // Seal a signing key
        let envelope =
            KeyProtectedKeyEnvelope::seal_signing(key_to_seal, wrapping_key, &ctx).unwrap();

        // Attempt to unseal as symmetric key
        assert!(matches!(
            envelope.unseal_symmetric(wrapping_key, &mut ctx),
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
        let envelope =
            KeyProtectedKeyEnvelope::seal_symmetric(key_to_seal, wrapping_key, &ctx).unwrap();

        // Serialize to string
        let serialized: String = envelope.into();

        // Deserialize from string
        let deserialized = KeyProtectedKeyEnvelope::from_str(&serialized).unwrap();

        // Unseal and verify
        let unsealed_key = deserialized
            .unseal_symmetric(wrapping_key, &mut ctx)
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
}

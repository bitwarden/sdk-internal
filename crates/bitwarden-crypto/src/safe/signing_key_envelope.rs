//! Wrapped signing key envelope for sealing a signing key with a symmetric key.

use std::str::FromStr;

use bitwarden_encoding::{B64, FromStrVisitor};
use coset::{CborSerializable, CoseEncrypt0Builder, HeaderBuilder};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    ContentFormat, CoseKeyBytes, CoseSerializable, KeySlotIds, KeyStoreContext, SigningKey,
    cose::{
        ContentNamespace, SafeObjectNamespace,
        symmetric::{CoseAlgorithmPolicy, decrypt_cose0, encrypt_cose0},
    },
    keys::KeyId,
    safe::{
        KeyEncryptionKey, KeyEncryptionKeyError, extract_key_id,
        helpers::{debug_fmt, set_safe_namespaces, validate_safe_namespaces},
        set_contained_key_id,
    },
};

/// Errors that can occur when sealing or unsealing a signing key with envelope operations.
#[derive(Debug, Error)]
pub enum SigningKeyEnvelopeError {
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
    /// The signing key envelope namespace is invalid.
    #[error("Invalid namespace")]
    InvalidNamespace,
}

impl From<KeyEncryptionKeyError> for SigningKeyEnvelopeError {
    fn from(error: KeyEncryptionKeyError) -> Self {
        match error {
            KeyEncryptionKeyError::Missing => SigningKeyEnvelopeError::KeyMissing,
            KeyEncryptionKeyError::WrongKeyType => SigningKeyEnvelopeError::WrongKeyType,
        }
    }
}

/// A signing key protected by a [`KeyEncryptionKey`]: an XAES-256-GCM or AES-256-CBC-HMAC
/// wrapping key. The signing key is sealed as a COSE key.
///
/// To migrate a key stored as an [`EncString`](crate::EncString), see
/// [`LegacyCompatSigningKeyEnvelope`](crate::compat::LegacyCompatSigningKeyEnvelope) and its
/// migration example.
#[derive(Clone)]
pub struct SigningKeyEnvelope {
    cose_encrypt0: coset::CoseEncrypt0,
}

impl SigningKeyEnvelope {
    /// Seals a signing key with a [`KeyEncryptionKey`] from the key store.
    pub fn seal<Ids: KeySlotIds>(
        key_to_seal: Ids::Signing,
        sealing_key: Ids::Symmetric,
        namespace: SigningKeyEnvelopeNamespace,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<Self, SigningKeyEnvelopeError> {
        // Get the keys from the key store.
        let key_to_seal = ctx
            .get_signing_key(key_to_seal)
            .map_err(|_| SigningKeyEnvelopeError::KeyMissing)?;
        let wrapping_key = KeyEncryptionKey::get_cose_key_view(ctx, sealing_key)?;

        let key_bytes = key_to_seal.to_cose();

        let mut protected_header = HeaderBuilder::from(ContentFormat::CoseKey).build();

        set_contained_key_id(&mut protected_header, Some(cose_key_id(&key_bytes)?));

        set_safe_namespaces(
            &mut protected_header,
            SafeObjectNamespace::SigningKeyEnvelope,
            namespace,
        );
        protected_header.key_id = wrapping_key.key_id().as_slice().into();

        let cose_encrypt0 = encrypt_cose0(
            wrapping_key.algorithm(),
            CoseEncrypt0Builder::new(),
            protected_header,
            key_bytes.as_ref(),
            wrapping_key.key_bytes(),
        )
        .map_err(|_| SigningKeyEnvelopeError::WrongKeyType)?;

        Ok(SigningKeyEnvelope { cose_encrypt0 })
    }

    /// Unseals a signing key with a [`KeyEncryptionKey`] and stores it in the key store context.
    pub fn unseal<Ids: KeySlotIds>(
        &self,
        wrapping_key: Ids::Symmetric,
        namespace: SigningKeyEnvelopeNamespace,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Signing, SigningKeyEnvelopeError> {
        let wrapping_key = KeyEncryptionKey::get_cose_key_view(ctx, wrapping_key)?;

        validate_safe_namespaces(
            &self.cose_encrypt0.protected.header,
            SafeObjectNamespace::SigningKeyEnvelope,
            namespace,
        )
        .map_err(|_| SigningKeyEnvelopeError::InvalidNamespace)?;

        // Require the protected algorithm to match the wrapping key's algorithm, so an envelope
        // sealed with one algorithm cannot be opened as another.
        let key_bytes = decrypt_cose0(
            &self.cose_encrypt0,
            CoseAlgorithmPolicy::Exactly(wrapping_key.algorithm()),
            wrapping_key.key_bytes(),
        )
        .map_err(|_| SigningKeyEnvelopeError::WrongKey)?;

        // Only a COSE key is a valid encoding for a sealed signing key.
        let content_format = ContentFormat::try_from(&self.cose_encrypt0.protected.header)
            .map_err(|_| SigningKeyEnvelopeError::Parsing("Invalid content format".to_string()))?;
        if content_format != ContentFormat::CoseKey {
            return Err(SigningKeyEnvelopeError::WrongKeyType);
        }

        let key = SigningKey::from_cose(&CoseKeyBytes::from(key_bytes))
            .map_err(|_| SigningKeyEnvelopeError::WrongKeyType)?;

        Ok(ctx.add_local_signing_key(key))
    }

    /// Get the key ID of the contained key.
    pub fn contained_key_id(&self) -> Result<Option<KeyId>, SigningKeyEnvelopeError> {
        extract_key_id(&self.cose_encrypt0.protected.header)
            .map_err(|_| SigningKeyEnvelopeError::Parsing("Invalid contained key id".to_string()))
    }

    /// Get the key ID of the key this envelope was sealed with. Always present in a well-formed
    /// envelope.
    pub fn encrypted_by_key_id(&self) -> Result<KeyId, SigningKeyEnvelopeError> {
        KeyId::try_from(self.cose_encrypt0.protected.header.key_id.as_slice())
            .map_err(|_| SigningKeyEnvelopeError::Parsing("Invalid sealing key id".to_string()))
    }
}

/// Reads the key ID from a serialized signing key, which always carries one.
fn cose_key_id(key_bytes: &CoseKeyBytes) -> Result<KeyId, SigningKeyEnvelopeError> {
    let cose_key = coset::CoseKey::from_slice(key_bytes.as_ref())
        .map_err(|_| SigningKeyEnvelopeError::WrongKeyType)?;
    KeyId::try_from(cose_key.key_id.as_slice()).map_err(|_| SigningKeyEnvelopeError::WrongKeyType)
}

impl From<&SigningKeyEnvelope> for Vec<u8> {
    fn from(val: &SigningKeyEnvelope) -> Self {
        val.cose_encrypt0
            .clone()
            .to_vec()
            .expect("Serialization to cose should not fail")
    }
}

impl TryFrom<&Vec<u8>> for SigningKeyEnvelope {
    type Error = coset::CoseError;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        let cose_encrypt0 = coset::CoseEncrypt0::from_slice(value)?;
        Ok(SigningKeyEnvelope { cose_encrypt0 })
    }
}

impl std::fmt::Debug for SigningKeyEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("SigningKeyEnvelope");

        if !self.cose_encrypt0.protected.header.key_id.is_empty() {
            s.field(
                "sealing_key_id",
                &self.cose_encrypt0.protected.header.key_id,
            );
        }

        debug_fmt::<SigningKeyEnvelopeNamespace>(&mut s, &self.cose_encrypt0.protected.header);

        if let Ok(Some(key_id)) = self.contained_key_id() {
            s.field("contained_key_id", &key_id);
        }

        s.finish()
    }
}

impl FromStr for SigningKeyEnvelope {
    type Err = SigningKeyEnvelopeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = B64::try_from(s).map_err(|_| {
            SigningKeyEnvelopeError::Parsing(
                "Invalid SigningKeyEnvelope Base64 encoding".to_string(),
            )
        })?;
        Self::try_from(&data.into_bytes()).map_err(|_| {
            SigningKeyEnvelopeError::Parsing("Failed to parse SigningKeyEnvelope".to_string())
        })
    }
}

impl From<SigningKeyEnvelope> for String {
    fn from(val: SigningKeyEnvelope) -> Self {
        let serialized: Vec<u8> = (&val).into();
        B64::from(serialized).to_string()
    }
}

impl<'de> Deserialize<'de> for SigningKeyEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new())
    }
}

impl Serialize for SigningKeyEnvelope {
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
export type SigningKeyEnvelope = Tagged<string, "SigningKeyEnvelope">;
"#;

bitwarden_ffi::impl_wire_string!(SigningKeyEnvelope, parse = |wire: String| wire.parse());

/// Content namespace for the signing key envelope
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum SigningKeyEnvelopeNamespace {
    /// The user's signing key, sealed with the user key
    UserSigningKey = 1,
    #[cfg(test)]
    /// Example namespace for testing purposes.
    ExampleNamespace = -3,
    #[cfg(test)]
    /// Another example namespace for testing purposes.
    ExampleNamespace2 = -4,
}

impl SigningKeyEnvelopeNamespace {
    /// Returns the numeric value of the namespace.
    pub fn as_i64(&self) -> i64 {
        *self as i64
    }
}

impl TryFrom<i128> for SigningKeyEnvelopeNamespace {
    type Error = SigningKeyEnvelopeError;

    fn try_from(value: i128) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(SigningKeyEnvelopeNamespace::UserSigningKey),
            #[cfg(test)]
            -3 => Ok(SigningKeyEnvelopeNamespace::ExampleNamespace),
            #[cfg(test)]
            -4 => Ok(SigningKeyEnvelopeNamespace::ExampleNamespace2),
            _ => Err(SigningKeyEnvelopeError::InvalidNamespace),
        }
    }
}

impl TryFrom<i64> for SigningKeyEnvelopeNamespace {
    type Error = SigningKeyEnvelopeError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        Self::try_from(i128::from(value))
    }
}

impl From<SigningKeyEnvelopeNamespace> for i128 {
    fn from(value: SigningKeyEnvelopeNamespace) -> Self {
        value.as_i64().into()
    }
}

impl ContentNamespace for SigningKeyEnvelopeNamespace {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        KeyStore, SignatureAlgorithm, SymmetricCryptoKey, SymmetricKeyAlgorithm,
        cose::{AES_256_CBC_HMAC_SHA256_AEAD, XAES_256_GCM},
        traits::tests::{TestIds, TestSigningKey, TestSymmKey},
    };

    const NAMESPACE: SigningKeyEnvelopeNamespace = SigningKeyEnvelopeNamespace::ExampleNamespace;

    const TEST_VECTOR_XAES256_GCM_ED25519_SEALING_KEY: &str = "pQEEAlAT9C5kyZlHASF1jKogP7qnAzoAARF5BIQDBAUGIFggRLAtRVLoREU81g2h8fOLP4QFVfV+InuxfjafsEcW7Y4B";
    const TEST_VECTOR_XAES256_GCM_ED25519_KEY_TO_SEAL: &str =
        "pgEBAlD+zvkfG2/trQt1+rvR/Pn0AycEgQEjWCDPKXDUr9XxzgHxzct9mcEBiMQDCP1K7Q6T9+P7G/uq3yAG";
    const TEST_VECTOR_XAES256_GCM_ED25519_ENVELOPE: &str = "g1g+pgE6AAEReQMYZQRQE/QuZMmZRwEhdYyqID+6pzoAARVcUP7O+R8bb+2tC3X6u9H8+fQ6AAE4gQU6AAE4gCKhBVgYZeshVJCjccwXBUQMrOtIBdPO6tjydjjRWE8t73VWu0LJqC8u3UyvU4b+1UkmumCIerqchsQxUQkI4BNHFrsbwLXszjBV/1jvdoUt+MvfEIYcPNqGJcUCV1mtR6gYzKc6aaBnarZ3Faey";

    const TEST_VECTOR_AES256_CBC_HMAC_MLDSA44_SEALING_KEY: &str =
        "ZgX47BXVpYxgbjFXs67ja9xajC/lqAA6zWmIclTrW4OtDVhUMPDENZahpyBZ6jnNVy4SEHxzCZgjLiNe5vuiUQ==";
    const TEST_VECTOR_AES256_CBC_HMAC_MLDSA44_KEY_TO_SEAL: &str = "pgEHAlCNtAyynGyqjlNKmTZzoirMAzgvBIEBIFkFIOTQoBwEdyA8CoKAS8Znatizf58h4FNhLxvhIAX9HepVwGdXEWo8yMKQAQSvw3GsXmK2Ms0HzRo3xdUJfnBtG0lnauO6V7ac4Oer3UrADEncP/Ggi2a18i0xZRYgdVNbuusF+xu279JDkV+XorC/1hTGeNp/5IaDq9xqKTG33KQV4r+nTbGhC3XqsM4OOrb1w1NHiA2t6qNDl+5AN+bDlQfgBANZMas26inPs/dQ1J5WT3QyDQs6SdrTeAVTaNuhdmZ83owSiXVbwfxFPIJVJLm8eVKRYluL8LZfp2ncgTYU4xFeccODljGlXhMFZz29uF0/vdGCVFFp8lmq3j29z/33eeFmVZqvvVUTdeleAa16NzNk4D61c53Lt6hh6lgQRfzG5ye8OfC9Ya8jNSrdMVaRL0c6m7ZukKpffPv9y/rPbYAZzLq7FEnbl6tXp6UGEjfYQqacnjwspfd8k7OE28JNqxdyXaFSu+TVFODLFXnmU+Naiq/3NV3HrlurZTLZO1lYMr/sU22nqSbZxsc9uHHiRI1KjzLzWEugLJ9Xoid4y7U9TEr8SkZdKr2u7piR2VNkGHBV8ostwXYoXTplTHnkTVLVpG0Jc0R+SAd2xX6ykr3GfZxlG2CIwPs9T5j5fKy3YDrKeS2SxhA68W2zRAur/u/WjqvFqS7HGU7ttJ0pjchjK9hxoq9orGb/NyQvcLSkFL7U8JGPBvqslsbCDn7rnPHrccF+zvRrNAjXzFCBsSmNrtslxI9KqulJYsknD68zbRz5Z5hppyY2cQ2c2lSdymU5zuzrEBN7L+qhMKx5rWJxvKsXjvRbXwcTrfDQTPyo5oozJ3IF/7X6L6aDmKhpQoPQHyK3gJEDSo93pbK6YQLMNtDuIN1wB4WA+ak3Mf81LNUz/jxYPHamGyuJlZ4smyRkBbP4HUXMUCZudJ18U7dbqBIfhApbKJu94fDOjd8FIT/9ic9vdUAh3viYOVGFvBIYYAcAduxJSdXorT8MxhrB8V88cO2nvHrLO6BBH+2CgTIJhlP1oXiKErIn8JKAkLLKO7ROfEWcb30nByyS/tpr7rD4xgjePTldOF/fUhSlLXsROAoKWo7MUu0VKfHfCOcG8lUwVMjQ6kPffzm6+BtUPRWtrvWsohYRfH5QYlNmvVNDvL8AJ7Z/9lCtaY+Mj0/8Zvp0dIgjqrWbottiua8vIPkXBvjP01/UdJ/MsrqzaYODPnUVi4WcePu1rVO2+WNWE7Rpz1lPAQi4uvFFNdM4IBvh7mtmelWebn6YpWzjh403XEHrhc/D3TWXF7CwTQSpb4w+jLCfXyhL3vBgtYVHiwKvsCG0oWV6ysnlGgD+MTmfgFBpUpx5/KeLMB9OJxR5U7UadlAIhLQHucWEkBB13TdrKNOAtqGSAE/oHrzg42h6gwxiokNhZuIFqEDYORuA9BTLRQzNLPCla2t+giLwf7sAQRgHjrwmIKi72Mja5crJ4hP7nBAuN1beDAaSDEOO31sZCNxZsI3YQnhWWCWH24lJZGwWuH2CfrlN6Picw0imfuTCt8c0TkLHmx1dIJxBRJZ+kOichVEy6L3CBKB9VsK0EbPNJ/xJfSHcJ5vxN6jbVT+G1/SxazQyZV7zLCCyw+hMBY0IHsjPXjqd0Je7tYpEpFkyLg639MQTSZI9RjvS+hqRDLdCkv9E5o4V6HtyJJonQgZ5AquAbbCLNc+2r/KuAwH1UeiRMzGk7luxTcp7TfD6sSL+Nt7vEAYhWCAmCHGP3HkCRDQBNc5hGZS4oU8jQIB8NEYEoD3hZosjaQ==";
    const TEST_VECTOR_AES256_CBC_HMAC_MLDSA44_ENVELOPE: &str = "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";

    /// An envelope pinned as a test vector, the keys it was sealed from, and how to generate it.
    struct TestVector {
        /// Used in the generated constant names and in assertion messages.
        name: &'static str,
        sealing_key_algorithm: SymmetricKeyAlgorithm,
        key_to_seal_algorithm: SignatureAlgorithm,
        cose_algorithm: coset::Algorithm,
        sealing_key: &'static str,
        /// Base64 COSE key.
        key_to_seal: &'static str,
        envelope: &'static str,
    }

    /// Together, the vectors cover both wrapping key algorithms and both signature algorithms.
    const TEST_VECTORS: [TestVector; 2] = [
        TestVector {
            name: "XAES256_GCM_ED25519",
            sealing_key_algorithm: SymmetricKeyAlgorithm::XAes256Gcm,
            key_to_seal_algorithm: SignatureAlgorithm::Ed25519,
            cose_algorithm: coset::Algorithm::PrivateUse(XAES_256_GCM),
            sealing_key: TEST_VECTOR_XAES256_GCM_ED25519_SEALING_KEY,
            key_to_seal: TEST_VECTOR_XAES256_GCM_ED25519_KEY_TO_SEAL,
            envelope: TEST_VECTOR_XAES256_GCM_ED25519_ENVELOPE,
        },
        TestVector {
            name: "AES256_CBC_HMAC_MLDSA44",
            sealing_key_algorithm: SymmetricKeyAlgorithm::Aes256CbcHmac,
            key_to_seal_algorithm: SignatureAlgorithm::MlDsa44,
            cose_algorithm: coset::Algorithm::PrivateUse(AES_256_CBC_HMAC_SHA256_AEAD),
            sealing_key: TEST_VECTOR_AES256_CBC_HMAC_MLDSA44_SEALING_KEY,
            key_to_seal: TEST_VECTOR_AES256_CBC_HMAC_MLDSA44_KEY_TO_SEAL,
            envelope: TEST_VECTOR_AES256_CBC_HMAC_MLDSA44_ENVELOPE,
        },
    ];

    /// The supported wrapping key algorithms.
    const WRAPPING_KEY_ALGORITHMS: [SymmetricKeyAlgorithm; 2] = [
        SymmetricKeyAlgorithm::XAes256Gcm,
        SymmetricKeyAlgorithm::Aes256CbcHmac,
    ];

    /// The supported signature algorithms.
    const SIGNATURE_ALGORITHMS: [SignatureAlgorithm; 2] =
        [SignatureAlgorithm::Ed25519, SignatureAlgorithm::MlDsa44];

    fn to_cose(ctx: &KeyStoreContext<TestIds>, key: TestSigningKey) -> CoseKeyBytes {
        ctx.get_signing_key(key).unwrap().to_cose()
    }

    #[test]
    #[ignore = "Manual test to verify debug format"]
    fn test_debug() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let key_to_seal = ctx.make_signing_key(SignatureAlgorithm::Ed25519);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);

        let envelope = SigningKeyEnvelope::seal(key_to_seal, wrapping_key, NAMESPACE, &ctx);
        println!("{:?}", envelope);
    }

    #[test]
    fn test_seal_unseal() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        for wrapping_key_algorithm in WRAPPING_KEY_ALGORITHMS {
            for signature_algorithm in SIGNATURE_ALGORITHMS {
                let label = format!("{wrapping_key_algorithm:?} sealing {signature_algorithm:?}");
                let key_to_seal = ctx.make_signing_key(signature_algorithm);
                let wrapping_key = ctx.make_symmetric_key(wrapping_key_algorithm);

                let envelope =
                    SigningKeyEnvelope::seal(key_to_seal, wrapping_key, NAMESPACE, &ctx).unwrap();
                let unsealed_key = envelope.unseal(wrapping_key, NAMESPACE, &mut ctx).unwrap();

                assert_eq!(
                    to_cose(&ctx, unsealed_key),
                    to_cose(&ctx, key_to_seal),
                    "{label}"
                );
            }
        }
    }

    #[test]
    fn test_key_ids() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        for wrapping_key_algorithm in WRAPPING_KEY_ALGORITHMS {
            let key_to_seal = ctx.make_signing_key(SignatureAlgorithm::Ed25519);
            let wrapping_key = ctx.make_symmetric_key(wrapping_key_algorithm);

            let envelope =
                SigningKeyEnvelope::seal(key_to_seal, wrapping_key, NAMESPACE, &ctx).unwrap();

            assert_eq!(
                envelope.contained_key_id().unwrap(),
                Some(cose_key_id(&to_cose(&ctx, key_to_seal)).unwrap()),
                "{wrapping_key_algorithm:?}"
            );

            // An AES-256-CBC-HMAC key doesn't store a key ID, so `seal` has to write the ID derived
            // from the key material.
            let wrapping_key_id = ctx
                .get_symmetric_key(wrapping_key)
                .unwrap()
                .key_id()
                .expect("Wrapping keys have a key ID");
            assert_eq!(
                envelope.encrypted_by_key_id().unwrap(),
                wrapping_key_id,
                "{wrapping_key_algorithm:?}"
            );
        }
    }

    #[test]
    fn test_string_serialization() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let key_to_seal = ctx.make_signing_key(SignatureAlgorithm::Ed25519);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);

        let envelope =
            SigningKeyEnvelope::seal(key_to_seal, wrapping_key, NAMESPACE, &ctx).unwrap();

        let serialized: String = envelope.into();
        let deserialized = SigningKeyEnvelope::from_str(&serialized).unwrap();
        let unsealed_key = deserialized
            .unseal(wrapping_key, NAMESPACE, &mut ctx)
            .unwrap();

        assert_eq!(to_cose(&ctx, unsealed_key), to_cose(&ctx, key_to_seal));
    }

    #[test]
    fn test_wrong_key() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let key_to_seal = ctx.make_signing_key(SignatureAlgorithm::Ed25519);

        for wrapping_key_algorithm in WRAPPING_KEY_ALGORITHMS {
            let wrapping_key = ctx.make_symmetric_key(wrapping_key_algorithm);
            let wrong_key = ctx.make_symmetric_key(wrapping_key_algorithm);

            let envelope =
                SigningKeyEnvelope::seal(key_to_seal, wrapping_key, NAMESPACE, &ctx).unwrap();

            assert!(
                matches!(
                    envelope.unseal(wrong_key, NAMESPACE, &mut ctx),
                    Err(SigningKeyEnvelopeError::WrongKey)
                ),
                "{wrapping_key_algorithm:?}"
            );
        }
    }

    #[test]
    fn test_rejects_unsupported_wrapping_keys() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let key_to_seal = ctx.make_signing_key(SignatureAlgorithm::Ed25519);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
        let envelope =
            SigningKeyEnvelope::seal(key_to_seal, wrapping_key, NAMESPACE, &ctx).unwrap();

        let unsupported_wrapping_keys = [
            ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256Gcm),
            ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305),
        ];

        for unsupported_wrapping_key in unsupported_wrapping_keys {
            assert!(matches!(
                SigningKeyEnvelope::seal(key_to_seal, unsupported_wrapping_key, NAMESPACE, &ctx),
                Err(SigningKeyEnvelopeError::WrongKeyType)
            ));
            assert!(matches!(
                envelope.unseal(unsupported_wrapping_key, NAMESPACE, &mut ctx),
                Err(SigningKeyEnvelopeError::WrongKeyType)
            ));
        }
    }

    #[test]
    fn test_wrong_namespace() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let key_to_seal = ctx.make_signing_key(SignatureAlgorithm::Ed25519);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);

        let envelope =
            SigningKeyEnvelope::seal(key_to_seal, wrapping_key, NAMESPACE, &ctx).unwrap();

        assert!(matches!(
            envelope.unseal(
                wrapping_key,
                SigningKeyEnvelopeNamespace::ExampleNamespace2,
                &mut ctx
            ),
            Err(SigningKeyEnvelopeError::InvalidNamespace)
        ));
    }

    #[test]
    fn test_rejects_symmetric_key_envelope() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let key_to_seal = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);

        // A symmetric key envelope carries the symmetric key envelope object namespace, so it must
        // not open as a signing key envelope.
        let symmetric_envelope = crate::safe::SymmetricKeyEnvelope::seal(
            key_to_seal,
            wrapping_key,
            crate::safe::SymmetricKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();
        let serialized: String = symmetric_envelope.into();
        let envelope = SigningKeyEnvelope::from_str(&serialized).unwrap();

        assert!(matches!(
            envelope.unseal(wrapping_key, NAMESPACE, &mut ctx),
            Err(SigningKeyEnvelopeError::InvalidNamespace)
        ));
    }

    #[test]
    fn test_seal_missing_keys() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let key_to_seal = ctx.make_signing_key(SignatureAlgorithm::Ed25519);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);

        assert!(matches!(
            SigningKeyEnvelope::seal(key_to_seal, TestSymmKey::A(0), NAMESPACE, &ctx),
            Err(SigningKeyEnvelopeError::KeyMissing)
        ));
        assert!(matches!(
            SigningKeyEnvelope::seal(TestSigningKey::A(0), wrapping_key, NAMESPACE, &ctx),
            Err(SigningKeyEnvelopeError::KeyMissing)
        ));
    }

    #[test]
    fn test_unseal_missing_wrapping_key() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let key_to_seal = ctx.make_signing_key(SignatureAlgorithm::Ed25519);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
        let envelope =
            SigningKeyEnvelope::seal(key_to_seal, wrapping_key, NAMESPACE, &ctx).unwrap();

        assert!(matches!(
            envelope.unseal(TestSymmKey::A(0), NAMESPACE, &mut ctx),
            Err(SigningKeyEnvelopeError::KeyMissing)
        ));
    }

    #[test]
    #[ignore = "Generates test vectors; run manually"]
    fn generate_test_vectors() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        for vector in TEST_VECTORS {
            let key_to_seal = ctx.make_signing_key(vector.key_to_seal_algorithm);
            let wrapping_key = ctx.make_symmetric_key(vector.sealing_key_algorithm);

            let envelope =
                SigningKeyEnvelope::seal(key_to_seal, wrapping_key, NAMESPACE, &ctx).unwrap();

            let sealing_key = ctx.get_symmetric_key(wrapping_key).unwrap().to_encoded();
            println!(
                "const TEST_VECTOR_{}_SEALING_KEY: &str = \"{}\";",
                vector.name,
                B64::from(sealing_key.to_vec().as_slice())
            );
            println!(
                "const TEST_VECTOR_{}_KEY_TO_SEAL: &str = \"{}\";",
                vector.name,
                B64::from(to_cose(&ctx, key_to_seal).as_ref())
            );
            let serialized: String = envelope.into();
            println!(
                "const TEST_VECTOR_{}_ENVELOPE: &str = \"{serialized}\";",
                vector.name
            );
        }
    }

    #[test]
    fn decrypt_test_vectors() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        for vector in TEST_VECTORS {
            let sealing_key = ctx.add_local_symmetric_key(
                SymmetricCryptoKey::try_from(vector.sealing_key.to_string())
                    .expect("Failed to parse sealing key from test vector"),
            );
            assert_eq!(
                ctx.get_symmetric_key_algorithm(sealing_key).unwrap(),
                vector.sealing_key_algorithm,
                "{}",
                vector.name
            );
            let expected_key = CoseKeyBytes::from(
                B64::try_from(vector.key_to_seal)
                    .expect("Failed to parse key to seal from test vector")
                    .into_bytes(),
            );
            let expected_signing_key = SigningKey::from_cose(&expected_key)
                .expect("Failed to parse key to seal from test vector");
            assert_eq!(
                expected_signing_key.to_verifying_key().algorithm(),
                vector.key_to_seal_algorithm,
                "{}",
                vector.name
            );

            let envelope = SigningKeyEnvelope::from_str(vector.envelope).unwrap();

            // Pin the header fields that consumers rely on: the algorithm, the ID used to look up
            // the sealing key, and the ID of the contained key.
            let header = &envelope.cose_encrypt0.protected.header;
            assert_eq!(
                header.alg.as_ref(),
                Some(&vector.cose_algorithm),
                "{}",
                vector.name
            );
            assert_eq!(
                header.key_id,
                ctx.get_symmetric_key(sealing_key)
                    .unwrap()
                    .key_id()
                    .expect("Sealing keys have a key ID")
                    .as_slice(),
                "{}",
                vector.name
            );
            assert_eq!(
                envelope.contained_key_id().unwrap(),
                Some(cose_key_id(&expected_key).unwrap()),
                "{}",
                vector.name
            );

            let unsealed_key = envelope.unseal(sealing_key, NAMESPACE, &mut ctx).unwrap();
            assert_eq!(to_cose(&ctx, unsealed_key), expected_key, "{}", vector.name);
        }
    }
}

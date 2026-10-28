//! Wrapped symmetric key envelope for sealing a symmetric key with another symmetric key.

use std::str::FromStr;

use bitwarden_encoding::{B64, FromStrVisitor};
use coset::{CborSerializable, CoseEncrypt0Builder, HeaderBuilder};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    ContentFormat, EncodedSymmetricKey, KeySlotIds, KeyStoreContext,
    cose::{
        ContentNamespace, SafeObjectNamespace,
        symmetric::{CoseAlgorithmPolicy, decrypt_cose0, encrypt_cose0},
    },
    keys::KeyId,
    safe::{
        DecodeSealedKeyError, KeyEncryptionKey, KeyEncryptionKeyError, decode_sealed_symmetric_key,
        extract_key_id,
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

impl From<KeyEncryptionKeyError> for SymmetricKeyEnvelopeError {
    fn from(error: KeyEncryptionKeyError) -> Self {
        match error {
            KeyEncryptionKeyError::Missing => SymmetricKeyEnvelopeError::KeyMissing,
            KeyEncryptionKeyError::WrongKeyType => SymmetricKeyEnvelopeError::WrongKeyType,
        }
    }
}

/// A symmetric key protected by a [`KeyEncryptionKey`]: an XAES-256-GCM or AES-256-CBC-HMAC
/// wrapping key.
#[derive(Clone)]
pub struct SymmetricKeyEnvelope {
    cose_encrypt0: coset::CoseEncrypt0,
}

impl SymmetricKeyEnvelope {
    /// Seals a symmetric key with a [`KeyEncryptionKey`] from the key store.
    pub fn seal<Ids: KeySlotIds>(
        key_to_seal: Ids::Symmetric,
        sealing_key: Ids::Symmetric,
        namespace: SymmetricKeyEnvelopeNamespace,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<Self, SymmetricKeyEnvelopeError> {
        // Get the keys from the key store.
        let key_to_seal = ctx
            .get_symmetric_key(key_to_seal)
            .map_err(|_| SymmetricKeyEnvelopeError::KeyMissing)?;
        let wrapping_key = KeyEncryptionKey::get_cose_key_view(ctx, sealing_key)?;

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
        protected_header.key_id = wrapping_key.key_id().as_slice().into();

        let cose_encrypt0 = encrypt_cose0(
            wrapping_key.algorithm(),
            CoseEncrypt0Builder::new(),
            protected_header,
            &key_bytes,
            wrapping_key.key_bytes(),
        )
        .map_err(|_| SymmetricKeyEnvelopeError::WrongKeyType)?;

        Ok(SymmetricKeyEnvelope { cose_encrypt0 })
    }

    /// Unseals a symmetric key with a [`KeyEncryptionKey`] and stores it in the key store context.
    pub fn unseal<Ids: KeySlotIds>(
        &self,
        wrapping_key: Ids::Symmetric,
        namespace: SymmetricKeyEnvelopeNamespace,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Symmetric, SymmetricKeyEnvelopeError> {
        let wrapping_key = KeyEncryptionKey::get_cose_key_view(ctx, wrapping_key)?;

        validate_safe_namespaces(
            &self.cose_encrypt0.protected.header,
            SafeObjectNamespace::SymmetricKeyEnvelope,
            namespace,
        )
        .map_err(|_| SymmetricKeyEnvelopeError::InvalidNamespace)?;

        // The wrapping key is independently typed, so require the protected content-encryption
        // algorithm to match its algorithm before attempting decryption. This prevents an envelope
        // sealed with one algorithm from being opened as another.
        let key_bytes = decrypt_cose0(
            &self.cose_encrypt0,
            CoseAlgorithmPolicy::Exactly(wrapping_key.algorithm()),
            wrapping_key.key_bytes(),
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

bitwarden_ffi::impl_wire_string!(SymmetricKeyEnvelope, parse = |wire: String| wire.parse());

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
    use crate::{
        KeyStore, SymmetricCryptoKey, SymmetricKeyAlgorithm,
        cose::{AES_256_CBC_HMAC_SHA256_AEAD, XAES_256_GCM},
        traits::tests::{TestIds, TestSymmKey},
    };

    const TEST_VECTOR_XAES256_GCM_SEALING_KEY: &str = "pQEEAlAJiRm3TVKQVUpm9gqA4tm6AzoAARF5BIQDBAUGIFggQyO5bN7Uto3hpXUyqluuArn+zppBmhdnahDRJ6p4s84B";
    const TEST_VECTOR_XAES256_GCM_KEY_TO_SEAL: &str = "pQEEAlDpQoswNPD5xaz7sYLHZXXXAzoAARFvBIQDBAUGIFgg2YO7eUZhb9WSxxsGvdURTunDOBV0W4FRk9E4TV7c00QB";
    const TEST_VECTOR_XAES256_GCM_ENVELOPE: &str = "g1g+pgE6AAEReQMYZQRQCYkZt01SkFVKZvYKgOLZujoAARVcUOlCizA08PnFrPuxgsdlddc6AAE4gQM6AAE4gCKhBVgYLLX2iYq+Ko+2Hp2fByDfGd5AC0Lw4+zxWFS9n8fBbBKHfiarETj6Q3uRwZYpDS5p29MBEJW7WxOaf5Az51+Qtr8ugnoocUJhb8l6vmkDxFy1blU6iHuoBvpd+3MSFOeCdiuMLbKrf469fmUlDn0=";

    const TEST_VECTOR_AES256_CBC_HMAC_SEALING_KEY: &str =
        "Im4/NyElI5SFvB8AVPN3Gpc18YMzAM1K0sIFigkoSQdpLnOUbm4DRhOK0n8WRdcZAsEpzVHKp5o3no9PQBYRnQ==";
    const TEST_VECTOR_AES256_CBC_HMAC_KEY_TO_SEAL: &str =
        "ikiXBX+XX73bEzUvrCMazkXDGokzRKGMVxCQmcss4CvEbt0BH7l17EtGVk076s7KUFpG3ddh4s7ft4Zjdp1IZQ==";
    const TEST_VECTOR_AES256_CBC_HMAC_ENVELOPE: &str = "g1hgpgE6AAERegN4ImFwcGxpY2F0aW9uL3guYml0d2FyZGVuLmxlZ2FjeS1rZXkEUCXt6Q6vGxzVz4yiWQaeIVU6AAEVXFAHW3SH5xZ6K2Rbzk++yRd8OgABOIEDOgABOIAioQVQFoZH08X+KUh2fG9r/3KTAVhwEpdWDKgAXIDyqxsGOJwBGmM2wFc1qCeZMkSjHhNRyQ4b/JClrplC66Vb9TjNLmXVDyDSlvpGYmRIS2e3Hqfg4/fRjNp/8QEmNEddLIZNatT/tpM8AyYfaGSpaz/y3SmiUryPBy2L3cpeNC05vE14tA==";

    /// An envelope pinned as a test vector, the keys it was sealed from, and how to generate it.
    struct TestVector {
        /// Used in the generated constant names and in assertion messages.
        name: &'static str,
        sealing_key_algorithm: SymmetricKeyAlgorithm,
        key_to_seal_algorithm: SymmetricKeyAlgorithm,
        cose_algorithm: coset::Algorithm,
        sealing_key: &'static str,
        key_to_seal: &'static str,
        envelope: &'static str,
    }

    /// Together, the vectors cover both wrapping key algorithms and both encodings of the sealed
    /// key: a COSE-encoded key (XChaCha20-Poly1305) and an AES-256-CBC-HMAC key, which uses the
    /// legacy (non-COSE) encoding.
    const TEST_VECTORS: [TestVector; 2] = [
        TestVector {
            name: "XAES256_GCM",
            sealing_key_algorithm: SymmetricKeyAlgorithm::XAes256Gcm,
            key_to_seal_algorithm: SymmetricKeyAlgorithm::XChaCha20Poly1305,
            cose_algorithm: coset::Algorithm::PrivateUse(XAES_256_GCM),
            sealing_key: TEST_VECTOR_XAES256_GCM_SEALING_KEY,
            key_to_seal: TEST_VECTOR_XAES256_GCM_KEY_TO_SEAL,
            envelope: TEST_VECTOR_XAES256_GCM_ENVELOPE,
        },
        TestVector {
            name: "AES256_CBC_HMAC",
            sealing_key_algorithm: SymmetricKeyAlgorithm::Aes256CbcHmac,
            key_to_seal_algorithm: SymmetricKeyAlgorithm::Aes256CbcHmac,
            cose_algorithm: coset::Algorithm::PrivateUse(AES_256_CBC_HMAC_SHA256_AEAD),
            sealing_key: TEST_VECTOR_AES256_CBC_HMAC_SEALING_KEY,
            key_to_seal: TEST_VECTOR_AES256_CBC_HMAC_KEY_TO_SEAL,
            envelope: TEST_VECTOR_AES256_CBC_HMAC_ENVELOPE,
        },
    ];

    /// The supported wrapping key algorithms, each paired with the COSE algorithm that an envelope
    /// sealed with such a key declares in its protected header.
    fn wrapping_key_algorithms() -> [(SymmetricKeyAlgorithm, coset::Algorithm); 2] {
        [
            (
                SymmetricKeyAlgorithm::XAes256Gcm,
                coset::Algorithm::PrivateUse(XAES_256_GCM),
            ),
            (
                SymmetricKeyAlgorithm::Aes256CbcHmac,
                coset::Algorithm::PrivateUse(AES_256_CBC_HMAC_SHA256_AEAD),
            ),
        ]
    }

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

        for (wrapping_key_algorithm, cose_algorithm) in wrapping_key_algorithms() {
            // AES-256-CBC-HMAC keys use the legacy (non-COSE) encoding, so they are sealed with a
            // different content format than the COSE-encoded key types.
            for key_to_seal_algorithm in [
                SymmetricKeyAlgorithm::Aes256CbcHmac,
                SymmetricKeyAlgorithm::XChaCha20Poly1305,
                SymmetricKeyAlgorithm::Aes256Gcm,
                SymmetricKeyAlgorithm::XAes256Gcm,
            ] {
                let key_to_seal = ctx.make_symmetric_key(key_to_seal_algorithm);
                let wrapping_key = ctx.make_symmetric_key(wrapping_key_algorithm);

                let envelope = SymmetricKeyEnvelope::seal(
                    key_to_seal,
                    wrapping_key,
                    SymmetricKeyEnvelopeNamespace::ExampleNamespace,
                    &ctx,
                )
                .unwrap();

                assert_eq!(
                    envelope.cose_encrypt0.protected.header.alg.as_ref(),
                    Some(&cose_algorithm),
                    "{wrapping_key_algorithm:?} sealing {key_to_seal_algorithm:?}"
                );

                let unsealed_key = envelope
                    .unseal(
                        wrapping_key,
                        SymmetricKeyEnvelopeNamespace::ExampleNamespace,
                        &mut ctx,
                    )
                    .unwrap();

                ctx.assert_symmetric_keys_equal(unsealed_key, key_to_seal);
            }
        }
    }

    #[test]
    fn test_key_ids_symmetric() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        for (wrapping_key_algorithm, _) in wrapping_key_algorithms() {
            let key_to_seal = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
            let wrapping_key = ctx.make_symmetric_key(wrapping_key_algorithm);

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
            assert_eq!(
                key_to_seal_ref.key_id(),
                envelope.contained_key_id().unwrap(),
                "{wrapping_key_algorithm:?}"
            );

            // An AES-256-CBC-HMAC key doesn't store a key ID, so `seal` has to write the ID derived
            // from the key material.
            let wrapping_key_id = ctx
                .get_symmetric_key(wrapping_key)
                .expect("Key should exist in the key store")
                .key_id()
                .expect("Wrapping keys have a key ID");
            assert_eq!(
                envelope.cose_encrypt0.protected.header.key_id,
                wrapping_key_id.as_slice(),
                "{wrapping_key_algorithm:?}"
            );
        }
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

        for (wrapping_key_algorithm, _) in wrapping_key_algorithms() {
            let key_to_seal = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
            let wrapping_key = ctx.make_symmetric_key(wrapping_key_algorithm);
            let wrong_key = ctx.make_symmetric_key(wrapping_key_algorithm);

            let envelope = SymmetricKeyEnvelope::seal(
                key_to_seal,
                wrapping_key,
                SymmetricKeyEnvelopeNamespace::ExampleNamespace,
                &ctx,
            )
            .unwrap();

            assert!(
                matches!(
                    envelope.unseal(
                        wrong_key,
                        SymmetricKeyEnvelopeNamespace::ExampleNamespace,
                        &mut ctx
                    ),
                    Err(SymmetricKeyEnvelopeError::WrongKey)
                ),
                "{wrapping_key_algorithm:?}"
            );
        }
    }

    #[test]
    fn test_rejects_unsupported_wrapping_keys() {
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
            // Without the key type check, `unseal` would attempt decryption and fail with
            // `WrongKey` instead.
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
    fn test_seal_missing_wrapping_key() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let missing_key = TestSymmKey::A(0);

        assert!(matches!(
            SymmetricKeyEnvelope::seal(
                key_to_seal,
                missing_key,
                SymmetricKeyEnvelopeNamespace::ExampleNamespace,
                &ctx,
            ),
            Err(SymmetricKeyEnvelopeError::KeyMissing)
        ));
    }

    #[test]
    fn test_unseal_missing_wrapping_key() {
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

        let missing_key = TestSymmKey::A(0);

        assert!(matches!(
            envelope.unseal(
                missing_key,
                SymmetricKeyEnvelopeNamespace::ExampleNamespace,
                &mut ctx,
            ),
            Err(SymmetricKeyEnvelopeError::KeyMissing)
        ));
    }

    #[test]
    #[ignore = "Generates test vectors; run manually"]
    fn generate_test_vectors() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        for vector in TEST_VECTORS {
            let key_to_seal = ctx.make_symmetric_key(vector.key_to_seal_algorithm);
            let wrapping_key = ctx.make_symmetric_key(vector.sealing_key_algorithm);

            let envelope = SymmetricKeyEnvelope::seal(
                key_to_seal,
                wrapping_key,
                SymmetricKeyEnvelopeNamespace::ExampleNamespace,
                &ctx,
            )
            .unwrap();

            for (key_name, key) in [("SEALING_KEY", wrapping_key), ("KEY_TO_SEAL", key_to_seal)] {
                println!(
                    "const TEST_VECTOR_{}_{key_name}: &str = \"{}\";",
                    vector.name,
                    B64::from(
                        ctx.get_symmetric_key(key)
                            .unwrap()
                            .to_encoded()
                            .to_vec()
                            .as_slice()
                    )
                );
            }
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
            let key_to_seal_test_vector = ctx.add_local_symmetric_key(
                SymmetricCryptoKey::try_from(vector.key_to_seal.to_string())
                    .expect("Failed to parse key to seal from test vector"),
            );
            assert_eq!(
                ctx.get_symmetric_key_algorithm(sealing_key).unwrap(),
                vector.sealing_key_algorithm,
                "{}",
                vector.name
            );
            assert_eq!(
                ctx.get_symmetric_key_algorithm(key_to_seal_test_vector)
                    .unwrap(),
                vector.key_to_seal_algorithm,
                "{}",
                vector.name
            );

            let envelope = SymmetricKeyEnvelope::from_str(vector.envelope).unwrap();

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
                ctx.get_symmetric_key(key_to_seal_test_vector)
                    .unwrap()
                    .key_id(),
                "{}",
                vector.name
            );

            let unsealed_key = envelope
                .unseal(
                    sealing_key,
                    SymmetricKeyEnvelopeNamespace::ExampleNamespace,
                    &mut ctx,
                )
                .unwrap();
            ctx.assert_symmetric_keys_equal(unsealed_key, key_to_seal_test_vector);
        }
    }
}

//! A wrapped signing key that is either a legacy [`EncString`] or a [`SigningKeyEnvelope`].
//!
//! Use it as the type of a stored wrapped-key field while migrating from [`EncString`] to
//! [`SigningKeyEnvelope`]: both formats deserialize, [`LegacyCompatSigningKeyEnvelope::seal`]
//! always produces the envelope, [`LegacyCompatSigningKeyEnvelope::seal_legacy`] the
//! [`EncString`].
//!
//! In order to migrate, add support via `seal_legacy`, then three full releases later, switch to
//! `seal`. This is a breaking change: older clients cannot read the envelope.
//!
//! ```text
//!   stored field ──deserialize──► EncString ────────────┐
//!                               └► SigningKeyEnvelope ──┴─unseal─► key ─seal─► SigningKeyEnvelope
//! ```

use std::str::FromStr;

use bitwarden_encoding::{B64, FromStrVisitor};
use serde::{Deserialize, Serialize};

use crate::{
    CryptoError, EncString, KeySlotIds, KeyStoreContext,
    keys::KeyId,
    safe::{SigningKeyEnvelope, SigningKeyEnvelopeError, SigningKeyEnvelopeNamespace},
};

/// Separates the type prefix from the payload in an [`EncString`], e.g. `2.iv|data|mac`. Base64,
/// used by [`SigningKeyEnvelope`], never contains it.
const ENC_STRING_TYPE_SEPARATOR: char = '.';

/// A signing key wrapped either as a legacy [`EncString`] or as a [`SigningKeyEnvelope`].
///
/// In order to migrate, add support via [`seal_legacy`](Self::seal_legacy), then three full
/// releases later, switch to [`seal`](Self::seal). This is a breaking change.
///
/// See the [migration example](https://github.com/bitwarden/sdk-internal/blob/main/crates/bitwarden-crypto/examples/migrate_wrapped_signing_key_from_encstring.rs).
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum LegacyCompatSigningKeyEnvelope {
    /// Legacy format. Has no namespace, so the namespace is not validated on unseal.
    EncString(EncString),
    /// Current format.
    SigningKeyEnvelope(SigningKeyEnvelope),
}

impl LegacyCompatSigningKeyEnvelope {
    /// Seals a signing key with an XAES-256-GCM or AES-256-CBC-HMAC key from the key store.
    /// Always produces the [`SigningKeyEnvelope`] variant.
    pub fn seal<Ids: KeySlotIds>(
        key_to_seal: Ids::Signing,
        sealing_key: Ids::Symmetric,
        namespace: SigningKeyEnvelopeNamespace,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<Self, SigningKeyEnvelopeError> {
        SigningKeyEnvelope::seal(key_to_seal, sealing_key, namespace, ctx)
            .map(Self::SigningKeyEnvelope)
    }

    /// Seals a signing key as a legacy [`EncString`], readable by clients that predate
    /// [`SigningKeyEnvelope`]. Always produces the [`EncString`] variant. The `namespace` is
    /// unused; it keeps the signature identical to [`seal`](Self::seal).
    ///
    /// In order to migrate, add support via `seal_legacy`, then three full releases later, switch
    /// to `seal`. This is a breaking change.
    pub fn seal_legacy<Ids: KeySlotIds>(
        key_to_seal: Ids::Signing,
        sealing_key: Ids::Symmetric,
        _namespace: SigningKeyEnvelopeNamespace,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<Self, SigningKeyEnvelopeError> {
        ctx.wrap_signing_key(sealing_key, key_to_seal)
            .map(Self::EncString)
            .map_err(map_legacy_error)
    }

    /// Unseals a signing key and stores it in the key store context.
    ///
    /// The `namespace` is only validated for the [`SigningKeyEnvelope`] variant.
    pub fn unseal<Ids: KeySlotIds>(
        &self,
        wrapping_key: Ids::Symmetric,
        namespace: SigningKeyEnvelopeNamespace,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Signing, SigningKeyEnvelopeError> {
        match self {
            Self::SigningKeyEnvelope(envelope) => envelope.unseal(wrapping_key, namespace, ctx),
            Self::EncString(enc_string) => ctx
                .unwrap_signing_key(wrapping_key, enc_string)
                .map_err(map_legacy_error),
        }
    }

    /// Get the key ID of the contained key. Returns `None` for the [`EncString`]
    pub fn contained_key_id(&self) -> Result<Option<KeyId>, SigningKeyEnvelopeError> {
        match self {
            Self::SigningKeyEnvelope(envelope) => envelope.contained_key_id(),
            Self::EncString(_) => Ok(None),
        }
    }

    /// Get the key ID of the key this was sealed with. Always present for the
    /// [`SigningKeyEnvelope`] variant; for the [`EncString`] variant, see [`EncString::key_id`].
    pub fn encrypted_by_key_id(&self) -> Result<Option<KeyId>, SigningKeyEnvelopeError> {
        match self {
            Self::SigningKeyEnvelope(envelope) => envelope.encrypted_by_key_id().map(Some),
            Self::EncString(enc_string) => Ok(enc_string.key_id()),
        }
    }
}

/// Maps key store [`EncString`] wrap/unwrap errors onto the envelope error type.
fn map_legacy_error(error: CryptoError) -> SigningKeyEnvelopeError {
    match error {
        CryptoError::MissingKeyId(_) => SigningKeyEnvelopeError::KeyMissing,
        CryptoError::ReadOnlyKeyStore => SigningKeyEnvelopeError::KeyStore,
        CryptoError::InvalidKey
        | CryptoError::WrongKeyType
        | CryptoError::OperationNotSupported(_) => SigningKeyEnvelopeError::WrongKeyType,
        _ => SigningKeyEnvelopeError::WrongKey,
    }
}

impl FromStr for LegacyCompatSigningKeyEnvelope {
    type Err = SigningKeyEnvelopeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.contains(ENC_STRING_TYPE_SEPARATOR) {
            return SigningKeyEnvelope::from_str(s).map(Self::SigningKeyEnvelope);
        }

        // Lax parsing: malformed EncStrings become `EncString::Unparseable`, preserving the raw
        // value on re-serialization. They fail on unseal instead.
        Ok(Self::EncString(EncString::from(s)))
    }
}

// `Display` is not implemented, matching [`EncString`]: `Debug` prints the decoded value,
// `ToString` the serialized form.
#[allow(clippy::to_string_trait_impl)]
impl ToString for LegacyCompatSigningKeyEnvelope {
    fn to_string(&self) -> String {
        match self {
            Self::EncString(enc_string) => enc_string.to_string(),
            Self::SigningKeyEnvelope(envelope) => {
                let serialized: Vec<u8> = envelope.into();
                B64::from(serialized).to_string()
            }
        }
    }
}

impl<'de> Deserialize<'de> for LegacyCompatSigningKeyEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new())
    }
}

impl Serialize for LegacyCompatSigningKeyEnvelope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::EncString(enc_string) => enc_string.serialize(serializer),
            Self::SigningKeyEnvelope(envelope) => envelope.serialize(serializer),
        }
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export type LegacyCompatSigningKeyEnvelope = Tagged<string, "LegacyCompatSigningKeyEnvelope">;
"#;

bitwarden_ffi::impl_wire_string!(LegacyCompatSigningKeyEnvelope);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CoseKeyBytes, CoseSerializable, KeyStore, SignatureAlgorithm, SymmetricCryptoKey,
        SymmetricKeyAlgorithm,
        traits::tests::{TestIds, TestSigningKey},
    };

    const NAMESPACE: SigningKeyEnvelopeNamespace = SigningKeyEnvelopeNamespace::ExampleNamespace;

    /// A stored struct with a wrapped-key field, as a consumer would declare it.
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct WrappedKeyContainer {
        wrapped_key: LegacyCompatSigningKeyEnvelope,
    }

    const TEST_VECTOR_KEY_TO_SEAL: &str =
        "pgEBAlBMlZGAtL8q0W8ZIFjHQHjWAycEgQEjWCB2yZd+5Ci0EGzxbEjmdWVL3EWIe7Bx6V3JBZ3qUsa9fyAG";

    const TEST_VECTOR_ENCSTRING_AES256_CBC_HMAC_WRAPPING_KEY: &str =
        "ksXzDBDGSbKsTnQ4w8QT/hF8gRtlXKm6IAE8wDTCW9oDaxZDaD0cNW/PUGdAqMY/RPlc1sB0yhGulxv8hG6LSw==";
    const TEST_VECTOR_ENCSTRING_AES256_CBC_HMAC_JSON: &str = r#"{"wrappedKey":"2.3vSDI/NkpI060CfgcVggHw==|adxzm97iFBR5DluiWkXZS90BPBTJ9vK6TWxmxvBb3ljmOQNqbJxQXLnf7DFPiBerRbxxiqiCwNtknnC/Y2QS1Q==|45GSOFAzPHWYgnadGM8mRcf/FLMf4se30ERun7Ii/y8="}"#;

    const TEST_VECTOR_ENCSTRING_XAES256_GCM_WRAPPING_KEY: &str = "pQEEAlDp8FDyt0NYOmI/hIthQwuKAzoAARF5BIQDBAUGIFgga5lnpFWFqtgsRhXhokCuFSAi+eZ1UDnBdNtcGQOWeU8B";
    const TEST_VECTOR_ENCSTRING_XAES256_GCM_JSON: &str = r#"{"wrappedKey":"7.g1gcowE6AAEReQMYZQRQ6fBQ8rdDWDpiP4SLYUMLiqEFWBiDy1Kn+4w8BYpMq5lS7q5UxoGK1oxDUPhYT/WemqII+1yA/LO5XeoLEPecTohMVIRV9ndFSh0zBBPIGZPoKWXHfS5F82JkF5lPxqPipdUI7wwoIBXc248zLeO/DGQXV459bSA/vhecqY0="}"#;

    const TEST_VECTOR_ENVELOPE_AES256_CBC_HMAC_AEAD_WRAPPING_KEY: &str =
        "GXa+fVkdGoZUfYfA/tYxLa+d0omjiFT5YeiXPG/jH9fvpUggkvpFRQEAGPU6I6wpy1hVb5mWVWibfHcu8e8jVg==";
    const TEST_VECTOR_ENVELOPE_AES256_CBC_HMAC_AEAD_JSON: &str = r#"{"wrappedKey":"g1g+pgE6AAERegMYZQRQ4KkWfM//uQW0gtRJFbiDmDoAARVcUEyVkYC0vyrRbxkgWMdAeNY6AAE4gQU6AAE4gCKhBVC41brYH7ZU2H0PS5zD8tpcWGAFGpePVFjPEN5OQSAjoUD2xIQdOdvHuXNsY9Vo1+VfrN0f15R9iIZeAcS/Ibyhwwrpb/D/yPrXL2UQpHEupWVF3xJz1Fy2bH+niVWn26v3uj1h9tnGZUPozXCNX+VH9Zc="}"#;

    const TEST_VECTOR_ENVELOPE_XAES256_GCM_WRAPPING_KEY: &str = "pQEEAlBSjS+qB+qPq7uqWykeWGVSAzoAARF5BIQDBAUGIFggzQy94cf0EX3Em5D3/0KAqLVrVbMp/+2cE1/ymq7tJTMB";
    const TEST_VECTOR_ENVELOPE_XAES256_GCM_JSON: &str = r#"{"wrappedKey":"g1g+pgE6AAEReQMYZQRQUo0vqgfqj6u7qlspHlhlUjoAARVcUEyVkYC0vyrRbxkgWMdAeNY6AAE4gQU6AAE4gCKhBVgYLYEdVpdft8dKuUDeAUlfRxrfWEK151REWE8rhwnMHq0Z27r8o2PmKnI+1gebrq2PAwhdJfSXpJMIwBVy7OiUc9Xpij0XcB9vsuc3n6NIwEStgxtFfJFumz1jkSeZN/4gkyHHW7xZuq1v"}"#;

    fn to_b64(ctx: &KeyStoreContext<TestIds>, key: <TestIds as KeySlotIds>::Symmetric) -> String {
        B64::from(ctx.get_symmetric_key(key).unwrap().to_encoded().to_vec()).to_string()
    }

    fn to_cose(ctx: &KeyStoreContext<TestIds>, key: TestSigningKey) -> CoseKeyBytes {
        ctx.get_signing_key(key).unwrap().to_cose()
    }

    fn to_json(wrapped_key: LegacyCompatSigningKeyEnvelope) -> String {
        serde_json::to_string(&WrappedKeyContainer { wrapped_key }).unwrap()
    }

    fn make_ed25519_key(ctx: &mut KeyStoreContext<TestIds>) -> TestSigningKey {
        ctx.make_signing_key(SignatureAlgorithm::Ed25519)
    }

    #[test]
    #[ignore = "Generates test vectors; run manually"]
    fn generate_test_vectors() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = make_ed25519_key(&mut ctx);
        println!(
            "const TEST_VECTOR_KEY_TO_SEAL: &str = \"{}\";",
            B64::from(to_cose(&ctx, key_to_seal).as_ref())
        );

        // Legacy EncString vectors, produced the way existing clients wrap keys.
        for (name, algorithm) in [
            (
                "ENCSTRING_AES256_CBC_HMAC",
                SymmetricKeyAlgorithm::Aes256CbcHmac,
            ),
            ("ENCSTRING_XAES256_GCM", SymmetricKeyAlgorithm::XAes256Gcm),
        ] {
            let wrapping_key = ctx.make_symmetric_key(algorithm);
            let wrapped = ctx.wrap_signing_key(wrapping_key, key_to_seal).unwrap();
            print_vector(
                name,
                &to_b64(&ctx, wrapping_key),
                &to_json(LegacyCompatSigningKeyEnvelope::EncString(wrapped)),
            );
        }

        // SigningKeyEnvelope vectors.
        for (name, algorithm) in [
            (
                "ENVELOPE_AES256_CBC_HMAC_AEAD",
                SymmetricKeyAlgorithm::Aes256CbcHmac,
            ),
            ("ENVELOPE_XAES256_GCM", SymmetricKeyAlgorithm::XAes256Gcm),
        ] {
            let wrapping_key = ctx.make_symmetric_key(algorithm);
            let sealed =
                LegacyCompatSigningKeyEnvelope::seal(key_to_seal, wrapping_key, NAMESPACE, &ctx)
                    .unwrap();
            print_vector(name, &to_b64(&ctx, wrapping_key), &to_json(sealed));
        }
    }

    fn print_vector(name: &str, wrapping_key: &str, json: &str) {
        println!("const TEST_VECTOR_{name}_WRAPPING_KEY: &str = \"{wrapping_key}\";");
        println!("const TEST_VECTOR_{name}_JSON: &str = r#\"{json}\"#;");
    }

    /// Deserializes a JSON test vector, checks the variant, unseals it, and checks it re-serializes
    /// to the same JSON.
    fn assert_test_vector(wrapping_key: &str, json: &str, expect_enc_string: bool) {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let wrapping_key = SymmetricCryptoKey::try_from(wrapping_key.to_string()).unwrap();
        let wrapping_key = ctx.add_local_symmetric_key(wrapping_key);
        let expected_key = B64::try_from(TEST_VECTOR_KEY_TO_SEAL).unwrap().into_bytes();

        let container: WrappedKeyContainer = serde_json::from_str(json).unwrap();
        assert_eq!(
            matches!(
                container.wrapped_key,
                LegacyCompatSigningKeyEnvelope::EncString(_)
            ),
            expect_enc_string
        );

        let unsealed = container
            .wrapped_key
            .unseal(wrapping_key, NAMESPACE, &mut ctx)
            .unwrap();
        assert_eq!(to_cose(&ctx, unsealed).as_ref(), expected_key.as_slice());

        assert_eq!(serde_json::to_string(&container).unwrap(), json);
    }

    #[test]
    fn test_vector_encstring_aes256_cbc_hmac() {
        assert_test_vector(
            TEST_VECTOR_ENCSTRING_AES256_CBC_HMAC_WRAPPING_KEY,
            TEST_VECTOR_ENCSTRING_AES256_CBC_HMAC_JSON,
            true,
        );
    }

    #[test]
    fn test_vector_encstring_xaes256_gcm() {
        assert_test_vector(
            TEST_VECTOR_ENCSTRING_XAES256_GCM_WRAPPING_KEY,
            TEST_VECTOR_ENCSTRING_XAES256_GCM_JSON,
            true,
        );
    }

    #[test]
    fn test_vector_envelope_aes256_cbc_hmac_aead() {
        assert_test_vector(
            TEST_VECTOR_ENVELOPE_AES256_CBC_HMAC_AEAD_WRAPPING_KEY,
            TEST_VECTOR_ENVELOPE_AES256_CBC_HMAC_AEAD_JSON,
            false,
        );
    }

    #[test]
    fn test_vector_envelope_xaes256_gcm() {
        assert_test_vector(
            TEST_VECTOR_ENVELOPE_XAES256_GCM_WRAPPING_KEY,
            TEST_VECTOR_ENVELOPE_XAES256_GCM_JSON,
            false,
        );
    }

    #[test]
    fn test_vector_encrypted_by_key_id() {
        // EncString type 2 carries no key ID; every other format names its wrapping key.
        for (wrapping_key, json, has_key_id) in [
            (
                TEST_VECTOR_ENCSTRING_AES256_CBC_HMAC_WRAPPING_KEY,
                TEST_VECTOR_ENCSTRING_AES256_CBC_HMAC_JSON,
                false,
            ),
            (
                TEST_VECTOR_ENCSTRING_XAES256_GCM_WRAPPING_KEY,
                TEST_VECTOR_ENCSTRING_XAES256_GCM_JSON,
                true,
            ),
            (
                TEST_VECTOR_ENVELOPE_AES256_CBC_HMAC_AEAD_WRAPPING_KEY,
                TEST_VECTOR_ENVELOPE_AES256_CBC_HMAC_AEAD_JSON,
                true,
            ),
            (
                TEST_VECTOR_ENVELOPE_XAES256_GCM_WRAPPING_KEY,
                TEST_VECTOR_ENVELOPE_XAES256_GCM_JSON,
                true,
            ),
        ] {
            let wrapping_key = SymmetricCryptoKey::try_from(wrapping_key.to_string()).unwrap();
            let container: WrappedKeyContainer = serde_json::from_str(json).unwrap();

            let expected = has_key_id.then(|| wrapping_key.key_id()).flatten();
            assert_eq!(
                container.wrapped_key.encrypted_by_key_id().unwrap(),
                expected
            );
        }
    }

    #[test]
    fn test_seal_produces_envelope_and_unseals() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = make_ed25519_key(&mut ctx);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);

        let sealed =
            LegacyCompatSigningKeyEnvelope::seal(key_to_seal, wrapping_key, NAMESPACE, &ctx)
                .unwrap();
        assert!(matches!(
            sealed,
            LegacyCompatSigningKeyEnvelope::SigningKeyEnvelope(_)
        ));

        let unsealed = sealed.unseal(wrapping_key, NAMESPACE, &mut ctx).unwrap();
        assert_eq!(to_cose(&ctx, unsealed), to_cose(&ctx, key_to_seal));
    }

    #[test]
    fn test_seal_legacy_produces_encstring_and_unseals() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = make_ed25519_key(&mut ctx);

        for algorithm in [
            SymmetricKeyAlgorithm::Aes256CbcHmac,
            SymmetricKeyAlgorithm::XAes256Gcm,
        ] {
            let wrapping_key = ctx.make_symmetric_key(algorithm);

            let sealed = LegacyCompatSigningKeyEnvelope::seal_legacy(
                key_to_seal,
                wrapping_key,
                NAMESPACE,
                &ctx,
            )
            .unwrap();
            assert!(matches!(
                sealed,
                LegacyCompatSigningKeyEnvelope::EncString(_)
            ));

            let unsealed = sealed.unseal(wrapping_key, NAMESPACE, &mut ctx).unwrap();
            assert_eq!(to_cose(&ctx, unsealed), to_cose(&ctx, key_to_seal));
        }
    }

    #[test]
    fn test_string_round_trip_preserves_variant() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = make_ed25519_key(&mut ctx);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);

        let enc_string = LegacyCompatSigningKeyEnvelope::EncString(
            ctx.wrap_signing_key(wrapping_key, key_to_seal).unwrap(),
        );
        let envelope =
            LegacyCompatSigningKeyEnvelope::seal(key_to_seal, wrapping_key, NAMESPACE, &ctx)
                .unwrap();

        for wrapped in [enc_string, envelope] {
            let is_enc_string = matches!(wrapped, LegacyCompatSigningKeyEnvelope::EncString(_));

            let string = wrapped.to_string();
            let parsed = LegacyCompatSigningKeyEnvelope::from_str(&string).unwrap();

            assert_eq!(
                matches!(parsed, LegacyCompatSigningKeyEnvelope::EncString(_)),
                is_enc_string
            );
            let unsealed = parsed.unseal(wrapping_key, NAMESPACE, &mut ctx).unwrap();
            assert_eq!(to_cose(&ctx, unsealed), to_cose(&ctx, key_to_seal));
        }
    }

    #[test]
    fn test_encstring_wrong_key() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = make_ed25519_key(&mut ctx);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let wrong_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);

        let wrapped = LegacyCompatSigningKeyEnvelope::EncString(
            ctx.wrap_signing_key(wrapping_key, key_to_seal).unwrap(),
        );

        assert!(matches!(
            wrapped.unseal(wrong_key, NAMESPACE, &mut ctx),
            Err(SigningKeyEnvelopeError::WrongKey)
        ));
        assert_eq!(wrapped.contained_key_id().unwrap(), None);
    }

    #[test]
    fn test_unparseable_input_errors() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);

        // Malformed EncStrings parse laxly, round-trip unchanged, and fail on unseal.
        let unparseable = LegacyCompatSigningKeyEnvelope::from_str("9.garbage").unwrap();
        assert_eq!(unparseable.to_string(), "9.garbage");
        assert!(
            unparseable
                .unseal(wrapping_key, NAMESPACE, &mut ctx)
                .is_err()
        );

        assert!(LegacyCompatSigningKeyEnvelope::from_str("not base64!").is_err());
    }
}

//! A wrapped symmetric key that is either a legacy [`EncString`] or a [`SymmetricKeyEnvelope`].
//!
//! Use it as the type of a stored wrapped-key field while migrating from [`EncString`] to
//! [`SymmetricKeyEnvelope`]: both formats deserialize, [`LegacyCompatSymmetricKeyEnvelope::seal`]
//! always produces the envelope, [`LegacyCompatSymmetricKeyEnvelope::seal_legacy`] the
//! [`EncString`].
//!
//! In order to migrate, add support via `seal_legacy`, then three full releases later, switch to
//! `seal`. This is a breaking change: older clients cannot read the envelope.
//!
//! ```text
//!   stored field ──deserialize──► EncString ──────────────┐
//!                               └► SymmetricKeyEnvelope ──┴─unseal─► key ─seal─► SymmetricKeyEnvelope
//! ```

use std::str::FromStr;

use bitwarden_encoding::FromStrVisitor;
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use wasm_bindgen::convert::FromWasmAbi;

use crate::{
    CryptoError, EncString, KeySlotIds, KeyStoreContext,
    keys::KeyId,
    safe::{SymmetricKeyEnvelope, SymmetricKeyEnvelopeError, SymmetricKeyEnvelopeNamespace},
};

/// Separates the type prefix from the payload in an [`EncString`], e.g. `2.iv|data|mac`. Base64,
/// used by [`SymmetricKeyEnvelope`], never contains it.
const ENC_STRING_TYPE_SEPARATOR: char = '.';

/// A symmetric key wrapped either as a legacy [`EncString`] or as a [`SymmetricKeyEnvelope`].
///
/// In order to migrate, add support via [`seal_legacy`](Self::seal_legacy), then three full
/// releases later, switch to [`seal`](Self::seal). This is a breaking change.
///
/// See the [migration example](https://github.com/bitwarden/sdk-internal/blob/main/crates/bitwarden-crypto/examples/migrate_wrapped_symmetric_key_from_encstring.rs).
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum LegacyCompatSymmetricKeyEnvelope {
    /// Legacy format. Has no namespace, so the namespace is not validated on unseal.
    EncString(EncString),
    /// Current format.
    SymmetricKeyEnvelope(SymmetricKeyEnvelope),
}

impl LegacyCompatSymmetricKeyEnvelope {
    /// Seals a symmetric key with an XAES-256-GCM or AES-256-CBC-HMAC key from the key store.
    /// Always produces the [`SymmetricKeyEnvelope`] variant.
    pub fn seal<Ids: KeySlotIds>(
        key_to_seal: Ids::Symmetric,
        sealing_key: Ids::Symmetric,
        namespace: SymmetricKeyEnvelopeNamespace,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<Self, SymmetricKeyEnvelopeError> {
        SymmetricKeyEnvelope::seal(key_to_seal, sealing_key, namespace, ctx)
            .map(Self::SymmetricKeyEnvelope)
    }

    /// Seals a symmetric key as a legacy [`EncString`], readable by clients that predate
    /// [`SymmetricKeyEnvelope`]. Always produces the [`EncString`] variant. The `namespace` is
    /// unused; it keeps the signature identical to [`seal`](Self::seal).
    ///
    /// In order to migrate, add support via `seal_legacy`, then three full releases later, switch
    /// to `seal`. This is a breaking change.
    pub fn seal_legacy<Ids: KeySlotIds>(
        key_to_seal: Ids::Symmetric,
        sealing_key: Ids::Symmetric,
        _namespace: SymmetricKeyEnvelopeNamespace,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<Self, SymmetricKeyEnvelopeError> {
        ctx.wrap_symmetric_key(sealing_key, key_to_seal)
            .map(Self::EncString)
            .map_err(map_legacy_error)
    }

    /// Unseals a symmetric key and stores it in the key store context.
    ///
    /// The `namespace` is only validated for the [`SymmetricKeyEnvelope`] variant.
    pub fn unseal<Ids: KeySlotIds>(
        &self,
        wrapping_key: Ids::Symmetric,
        namespace: SymmetricKeyEnvelopeNamespace,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Symmetric, SymmetricKeyEnvelopeError> {
        match self {
            Self::SymmetricKeyEnvelope(envelope) => envelope.unseal(wrapping_key, namespace, ctx),
            Self::EncString(enc_string) => ctx
                .unwrap_symmetric_key(wrapping_key, enc_string)
                .map_err(map_legacy_error),
        }
    }

    /// Get the key ID of the contained key. Returns `None` for the [`EncString`]
    pub fn contained_key_id(&self) -> Result<Option<KeyId>, SymmetricKeyEnvelopeError> {
        match self {
            Self::SymmetricKeyEnvelope(envelope) => envelope.contained_key_id(),
            Self::EncString(_) => Ok(None),
        }
    }

    /// Get the key ID of the key this was sealed with. Always present for the
    /// [`SymmetricKeyEnvelope`] variant; for the [`EncString`] variant, see
    /// [`EncString::encrypted_by_key_id`].
    pub fn encrypted_by_key_id(&self) -> Result<Option<KeyId>, SymmetricKeyEnvelopeError> {
        match self {
            Self::SymmetricKeyEnvelope(envelope) => envelope.encrypted_by_key_id().map(Some),
            Self::EncString(enc_string) => Ok(enc_string.encrypted_by_key_id()),
        }
    }
}

/// Maps key store [`EncString`] wrap/unwrap errors onto the envelope error type.
fn map_legacy_error(error: CryptoError) -> SymmetricKeyEnvelopeError {
    match error {
        CryptoError::MissingKeyId(_) => SymmetricKeyEnvelopeError::KeyMissing,
        CryptoError::ReadOnlyKeyStore => SymmetricKeyEnvelopeError::KeyStore,
        CryptoError::InvalidKey
        | CryptoError::WrongKeyType
        | CryptoError::OperationNotSupported(_) => SymmetricKeyEnvelopeError::WrongKeyType,
        _ => SymmetricKeyEnvelopeError::WrongKey,
    }
}

impl FromStr for LegacyCompatSymmetricKeyEnvelope {
    type Err = SymmetricKeyEnvelopeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.contains(ENC_STRING_TYPE_SEPARATOR) {
            return SymmetricKeyEnvelope::from_str(s).map(Self::SymmetricKeyEnvelope);
        }

        EncString::parse_strict(s)
            .map(Self::EncString)
            .map_err(|_| {
                SymmetricKeyEnvelopeError::Parsing("Failed to parse EncString".to_string())
            })
    }
}

impl From<LegacyCompatSymmetricKeyEnvelope> for String {
    fn from(val: LegacyCompatSymmetricKeyEnvelope) -> Self {
        match val {
            LegacyCompatSymmetricKeyEnvelope::EncString(enc_string) => enc_string.to_string(),
            LegacyCompatSymmetricKeyEnvelope::SymmetricKeyEnvelope(envelope) => envelope.into(),
        }
    }
}

impl<'de> Deserialize<'de> for LegacyCompatSymmetricKeyEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new())
    }
}

impl Serialize for LegacyCompatSymmetricKeyEnvelope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::EncString(enc_string) => enc_string.serialize(serializer),
            Self::SymmetricKeyEnvelope(envelope) => envelope.serialize(serializer),
        }
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export type LegacyCompatSymmetricKeyEnvelope = Tagged<string, "LegacyCompatSymmetricKeyEnvelope">;
"#;

#[cfg(feature = "wasm")]
impl wasm_bindgen::describe::WasmDescribe for LegacyCompatSymmetricKeyEnvelope {
    fn describe() {
        <String as wasm_bindgen::describe::WasmDescribe>::describe();
    }
}

#[cfg(feature = "wasm")]
impl FromWasmAbi for LegacyCompatSymmetricKeyEnvelope {
    type Abi = <String as FromWasmAbi>::Abi;

    unsafe fn from_abi(abi: Self::Abi) -> Self {
        use wasm_bindgen::UnwrapThrowExt;
        let string = unsafe { String::from_abi(abi) };
        LegacyCompatSymmetricKeyEnvelope::from_str(&string).unwrap_throw()
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_encoding::B64;

    use super::*;
    use crate::{KeyStore, SymmetricCryptoKey, SymmetricKeyAlgorithm, traits::tests::TestIds};

    const NAMESPACE: SymmetricKeyEnvelopeNamespace =
        SymmetricKeyEnvelopeNamespace::ExampleNamespace;

    /// A stored struct with a wrapped-key field, as a consumer would declare it.
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct WrappedKeyContainer {
        wrapped_key: LegacyCompatSymmetricKeyEnvelope,
    }

    const TEST_VECTOR_KEY_TO_SEAL: &str =
        "BcyEWu7YAzYvJ7yS2apoqVZnQAGaIcqJ7bF3gZ6+M+PZOFCySUQFgfSsasWzMZ3FvuW+Dfs2XCpcY6u7Pro8Ng==";

    const TEST_VECTOR_ENCSTRING_AES256_CBC_HMAC_WRAPPING_KEY: &str =
        "zJn720+PbyN69qSpCQsC2kU26ZculfxQsEbpsl7DV3PC1/4yCT6UF+iZJ9r9iguxQOxvXZuLSdcnwgcAke4oxA==";
    const TEST_VECTOR_ENCSTRING_AES256_CBC_HMAC_JSON: &str = r#"{"wrappedKey":"2.hfUXMlC62NcbqULcned9JA==|Zs89DYhe9NvTI8cah/LqGZ11BmBNWlC+Xb/Oh7JtnbNCgSfcP816wFAf3OKR0ScLmZUE/AlgFqTp8ababErTloYGezAbt82OWHFdcw8ABhE=|ZqdshXwOPKOv8f/sRQTlu1Hym8ZJnvUoX7GCxxagOdc="}"#;

    const TEST_VECTOR_ENCSTRING_XAES256_GCM_WRAPPING_KEY: &str = "pQEEAlD+ZvKs0+kPMMTp4ClHkzQwAzoAARF5BIQDBAUGIFgg4FkbxCaU91bbTVw3e1cUO6S2oTqSISiySl5LrSfwOt8B";
    const TEST_VECTOR_ENCSTRING_XAES256_GCM_JSON: &str = r#"{"wrappedKey":"7.g1g+owE6AAEReQN4ImFwcGxpY2F0aW9uL3guYml0d2FyZGVuLmxlZ2FjeS1rZXkEUP5m8qzT6Q8wxOngKUeTNDChBVgYL4b8GbJ/8WekzkDiaijkGjFrpCco13sAWFDd+iZoFmFx6kspDvvpTpgtyyJ2z0pxISAEK7rnhK3YWoIiQ7O7kPgrM/tAU2juD2mUzdhbCF5kO7wQwhd54QJ91i2B3ySFccRAugZngAjKag=="}"#;

    const TEST_VECTOR_ENVELOPE_AES256_CBC_HMAC_AEAD_WRAPPING_KEY: &str =
        "+SsIO7+WtSM4LYvxoDTTCO8kU5uZ0UwDmjdsv8K/+dfHOfQV8pXJI3buVwtCZJAoAd+1teXUVckZeme9CkjDEQ==";
    const TEST_VECTOR_ENVELOPE_AES256_CBC_HMAC_AEAD_JSON: &str = r#"{"wrappedKey":"g1hgpgE6AAERegN4ImFwcGxpY2F0aW9uL3guYml0d2FyZGVuLmxlZ2FjeS1rZXkEUMlGtgwr6Y+fKwZUHeZw2M86AAEVXFBOFUXyYMu3MZtMG0+1s6weOgABOIEDOgABOIAioQVQokk1hPwmXf8MTufSj/kmXlhwneWfBQhZIqbfTLYNcurzmH4R1WL3B3o+rlsCve9kUpEgGCdVyw/jE1oKF+wXKIfhnbmFOxj4vONQPR9/Gy4QCF8Jy0LrbXCX0rYSbMGN3cv2ZLxoma3GjHbYZaEvEmhazFq0pIq3wp0S7jGnv4+0/A=="}"#;

    const TEST_VECTOR_ENVELOPE_XAES256_GCM_WRAPPING_KEY: &str = "pQEEAlDPARaWmpuJo+0BSEH+0Z8mAzoAARF5BIQDBAUGIFggQ95pSAOYnJtK9FggeIO8QBDtb/vr9LIM4wb+/W3pI8MB";
    const TEST_VECTOR_ENVELOPE_XAES256_GCM_JSON: &str = r#"{"wrappedKey":"g1hgpgE6AAEReQN4ImFwcGxpY2F0aW9uL3guYml0d2FyZGVuLmxlZ2FjeS1rZXkEUM8BFpaam4mj7QFIQf7RnyY6AAEVXFBOFUXyYMu3MZtMG0+1s6weOgABOIEDOgABOIAioQVYGC3aRnWqCU2AKkSnIhnvuw0BL4U239v5iVhQ6RpmuYoqvK660Q17JeCRvywXvfM0fQ6OccdJBBQr/RxE5D4N4rwp2T1tPWLRP0K40wfL/pNb4nKdPVY4GBe4dSlT5RN+UKabC7oe8YbpUVU="}"#;

    fn to_b64(ctx: &KeyStoreContext<TestIds>, key: <TestIds as KeySlotIds>::Symmetric) -> String {
        B64::from(ctx.get_symmetric_key(key).unwrap().to_encoded().to_vec()).to_string()
    }

    fn to_json(wrapped_key: LegacyCompatSymmetricKeyEnvelope) -> String {
        serde_json::to_string(&WrappedKeyContainer { wrapped_key }).unwrap()
    }

    #[test]
    #[ignore = "Generates test vectors; run manually"]
    fn generate_test_vectors() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
        println!(
            "const TEST_VECTOR_KEY_TO_SEAL: &str = \"{}\";",
            to_b64(&ctx, key_to_seal)
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
            let wrapped = ctx.wrap_symmetric_key(wrapping_key, key_to_seal).unwrap();
            print_vector(
                name,
                &to_b64(&ctx, wrapping_key),
                &to_json(LegacyCompatSymmetricKeyEnvelope::EncString(wrapped)),
            );
        }

        // SymmetricKeyEnvelope vectors.
        for (name, algorithm) in [
            (
                "ENVELOPE_AES256_CBC_HMAC_AEAD",
                SymmetricKeyAlgorithm::Aes256CbcHmac,
            ),
            ("ENVELOPE_XAES256_GCM", SymmetricKeyAlgorithm::XAes256Gcm),
        ] {
            let wrapping_key = ctx.make_symmetric_key(algorithm);
            let sealed =
                LegacyCompatSymmetricKeyEnvelope::seal(key_to_seal, wrapping_key, NAMESPACE, &ctx)
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
        let expected_key =
            SymmetricCryptoKey::try_from(TEST_VECTOR_KEY_TO_SEAL.to_string()).unwrap();

        let container: WrappedKeyContainer = serde_json::from_str(json).unwrap();
        assert_eq!(
            matches!(
                container.wrapped_key,
                LegacyCompatSymmetricKeyEnvelope::EncString(_)
            ),
            expect_enc_string
        );

        let unsealed = container
            .wrapped_key
            .unseal(wrapping_key, NAMESPACE, &mut ctx)
            .unwrap();
        assert_eq!(ctx.get_symmetric_key(unsealed).unwrap(), &expected_key);

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

        let key_to_seal = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);

        let sealed =
            LegacyCompatSymmetricKeyEnvelope::seal(key_to_seal, wrapping_key, NAMESPACE, &ctx)
                .unwrap();
        assert!(matches!(
            sealed,
            LegacyCompatSymmetricKeyEnvelope::SymmetricKeyEnvelope(_)
        ));

        let unsealed = sealed.unseal(wrapping_key, NAMESPACE, &mut ctx).unwrap();
        ctx.assert_symmetric_keys_equal(unsealed, key_to_seal);
    }

    #[test]
    fn test_seal_legacy_produces_encstring_and_unseals() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);

        for algorithm in [
            SymmetricKeyAlgorithm::Aes256CbcHmac,
            SymmetricKeyAlgorithm::XAes256Gcm,
        ] {
            let wrapping_key = ctx.make_symmetric_key(algorithm);

            let sealed = LegacyCompatSymmetricKeyEnvelope::seal_legacy(
                key_to_seal,
                wrapping_key,
                NAMESPACE,
                &ctx,
            )
            .unwrap();
            assert!(matches!(
                sealed,
                LegacyCompatSymmetricKeyEnvelope::EncString(_)
            ));

            let unsealed = sealed.unseal(wrapping_key, NAMESPACE, &mut ctx).unwrap();
            ctx.assert_symmetric_keys_equal(unsealed, key_to_seal);
        }
    }

    #[test]
    fn test_string_round_trip_preserves_variant() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);

        let enc_string = LegacyCompatSymmetricKeyEnvelope::EncString(
            ctx.wrap_symmetric_key(wrapping_key, key_to_seal).unwrap(),
        );
        let envelope =
            LegacyCompatSymmetricKeyEnvelope::seal(key_to_seal, wrapping_key, NAMESPACE, &ctx)
                .unwrap();

        for wrapped in [enc_string, envelope] {
            let is_enc_string = matches!(wrapped, LegacyCompatSymmetricKeyEnvelope::EncString(_));

            let string: String = wrapped.into();
            let parsed = LegacyCompatSymmetricKeyEnvelope::from_str(&string).unwrap();

            assert_eq!(
                matches!(parsed, LegacyCompatSymmetricKeyEnvelope::EncString(_)),
                is_enc_string
            );
            let unsealed = parsed.unseal(wrapping_key, NAMESPACE, &mut ctx).unwrap();
            ctx.assert_symmetric_keys_equal(unsealed, key_to_seal);
        }
    }

    #[test]
    fn test_encstring_wrong_key() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let wrong_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);

        let wrapped = LegacyCompatSymmetricKeyEnvelope::EncString(
            ctx.wrap_symmetric_key(wrapping_key, key_to_seal).unwrap(),
        );

        assert!(matches!(
            wrapped.unseal(wrong_key, NAMESPACE, &mut ctx),
            Err(SymmetricKeyEnvelopeError::WrongKey)
        ));
        assert_eq!(wrapped.contained_key_id().unwrap(), None);
    }

    #[test]
    fn test_unparseable_input_errors() {
        assert!(LegacyCompatSymmetricKeyEnvelope::from_str("9.garbage").is_err());
        assert!(LegacyCompatSymmetricKeyEnvelope::from_str("not base64!").is_err());
    }
}

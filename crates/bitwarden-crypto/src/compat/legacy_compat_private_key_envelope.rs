//! A wrapped private key that is either a legacy [`EncString`] or a [`PrivateKeyEnvelope`].
//!
//! Use it as the type of a stored wrapped-key field while migrating from [`EncString`] to
//! [`PrivateKeyEnvelope`]: both formats deserialize, [`LegacyCompatPrivateKeyEnvelope::seal`]
//! always produces the envelope, [`LegacyCompatPrivateKeyEnvelope::seal_legacy`] the
//! [`EncString`].
//!
//! In order to migrate, add support via `seal_legacy`, then three full releases later, switch to
//! `seal`. This is a breaking change: older clients cannot read the envelope.
//!
//! ```text
//!   stored field ──deserialize──► EncString ────────────┐
//!                               └► PrivateKeyEnvelope ──┴─unseal─► key ─seal─► PrivateKeyEnvelope
//! ```

use std::str::FromStr;

use bitwarden_encoding::{B64, FromStrVisitor};
use serde::{Deserialize, Serialize};

use crate::{
    CryptoError, EncString, KeySlotIds, KeyStoreContext,
    keys::KeyId,
    safe::{PrivateKeyEnvelope, PrivateKeyEnvelopeError, PrivateKeyEnvelopeNamespace},
};

/// Separates the type prefix from the payload in an [`EncString`], e.g. `2.iv|data|mac`. Base64,
/// used by [`PrivateKeyEnvelope`], never contains it.
const ENC_STRING_TYPE_SEPARATOR: char = '.';

/// A private key wrapped either as a legacy [`EncString`] or as a [`PrivateKeyEnvelope`].
///
/// In order to migrate, add support via [`seal_legacy`](Self::seal_legacy), then three full
/// releases later, switch to [`seal`](Self::seal). This is a breaking change.
///
/// See the [migration example](https://github.com/bitwarden/sdk-internal/blob/main/crates/bitwarden-crypto/examples/migrate_wrapped_private_key_from_encstring.rs).
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum LegacyCompatPrivateKeyEnvelope {
    /// Legacy format. Has no namespace, so the namespace is not validated on unseal.
    EncString(EncString),
    /// Current format.
    PrivateKeyEnvelope(PrivateKeyEnvelope),
}

impl LegacyCompatPrivateKeyEnvelope {
    /// Seals a private key with an XAES-256-GCM or AES-256-CBC-HMAC key from the key store.
    /// Always produces the [`PrivateKeyEnvelope`] variant.
    pub fn seal<Ids: KeySlotIds>(
        key_to_seal: Ids::Private,
        sealing_key: Ids::Symmetric,
        namespace: PrivateKeyEnvelopeNamespace,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<Self, PrivateKeyEnvelopeError> {
        PrivateKeyEnvelope::seal(key_to_seal, sealing_key, namespace, ctx)
            .map(Self::PrivateKeyEnvelope)
    }

    /// Seals a private key as a legacy [`EncString`], readable by clients that predate
    /// [`PrivateKeyEnvelope`]. Always produces the [`EncString`] variant. The `namespace` is
    /// unused; it keeps the signature identical to [`seal`](Self::seal).
    ///
    /// In order to migrate, add support via `seal_legacy`, then three full releases later, switch
    /// to `seal`. This is a breaking change.
    pub fn seal_legacy<Ids: KeySlotIds>(
        key_to_seal: Ids::Private,
        sealing_key: Ids::Symmetric,
        _namespace: PrivateKeyEnvelopeNamespace,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<Self, PrivateKeyEnvelopeError> {
        ctx.wrap_private_key(sealing_key, key_to_seal)
            .map(Self::EncString)
            .map_err(map_legacy_error)
    }

    /// Unseals a private key and stores it in the key store context.
    ///
    /// The `namespace` is only validated for the [`PrivateKeyEnvelope`] variant.
    pub fn unseal<Ids: KeySlotIds>(
        &self,
        wrapping_key: Ids::Symmetric,
        namespace: PrivateKeyEnvelopeNamespace,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Private, PrivateKeyEnvelopeError> {
        match self {
            Self::PrivateKeyEnvelope(envelope) => envelope.unseal(wrapping_key, namespace, ctx),
            Self::EncString(enc_string) => ctx
                .unwrap_private_key(wrapping_key, enc_string)
                .map_err(map_legacy_error),
        }
    }

    /// Get the key ID of the key this was sealed with. Always present for the
    /// [`PrivateKeyEnvelope`] variant; for the [`EncString`] variant, see [`EncString::key_id`].
    pub fn encrypted_by_key_id(&self) -> Result<Option<KeyId>, PrivateKeyEnvelopeError> {
        match self {
            Self::PrivateKeyEnvelope(envelope) => envelope.encrypted_by_key_id().map(Some),
            Self::EncString(enc_string) => Ok(enc_string.key_id()),
        }
    }
}

/// Maps key store [`EncString`] wrap/unwrap errors onto the envelope error type.
fn map_legacy_error(error: CryptoError) -> PrivateKeyEnvelopeError {
    match error {
        CryptoError::MissingKeyId(_) => PrivateKeyEnvelopeError::KeyMissing,
        CryptoError::ReadOnlyKeyStore => PrivateKeyEnvelopeError::KeyStore,
        CryptoError::InvalidKey
        | CryptoError::WrongKeyType
        | CryptoError::OperationNotSupported(_) => PrivateKeyEnvelopeError::WrongKeyType,
        _ => PrivateKeyEnvelopeError::WrongKey,
    }
}

impl FromStr for LegacyCompatPrivateKeyEnvelope {
    type Err = PrivateKeyEnvelopeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.contains(ENC_STRING_TYPE_SEPARATOR) {
            return PrivateKeyEnvelope::from_str(s).map(Self::PrivateKeyEnvelope);
        }

        // Lax parsing: malformed EncStrings become `EncString::Unparseable`, preserving the raw
        // value on re-serialization. They fail on unseal instead.
        Ok(Self::EncString(EncString::from(s)))
    }
}

// `Display` is not implemented, matching [`EncString`]: `Debug` prints the decoded value,
// `ToString` the serialized form.
#[allow(clippy::to_string_trait_impl)]
impl ToString for LegacyCompatPrivateKeyEnvelope {
    fn to_string(&self) -> String {
        match self {
            Self::EncString(enc_string) => enc_string.to_string(),
            Self::PrivateKeyEnvelope(envelope) => {
                let serialized: Vec<u8> = envelope.into();
                B64::from(serialized).to_string()
            }
        }
    }
}

impl<'de> Deserialize<'de> for LegacyCompatPrivateKeyEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new())
    }
}

impl Serialize for LegacyCompatPrivateKeyEnvelope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::EncString(enc_string) => enc_string.serialize(serializer),
            Self::PrivateKeyEnvelope(envelope) => envelope.serialize(serializer),
        }
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export type LegacyCompatPrivateKeyEnvelope = Tagged<string, "LegacyCompatPrivateKeyEnvelope">;
"#;

bitwarden_ffi::impl_wire_string!(LegacyCompatPrivateKeyEnvelope);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        KeyStore, Pkcs8PrivateKeyBytes, PublicKeyEncryptionAlgorithm, SymmetricCryptoKey,
        SymmetricKeyAlgorithm,
        traits::tests::{TestIds, TestPrivateKey},
    };

    const NAMESPACE: PrivateKeyEnvelopeNamespace = PrivateKeyEnvelopeNamespace::ExampleNamespace;

    /// A stored struct with a wrapped-key field, as a consumer would declare it.
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct WrappedKeyContainer {
        wrapped_key: LegacyCompatPrivateKeyEnvelope,
    }

    const TEST_VECTOR_KEY_TO_SEAL: &str = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC96LaNZUy9do+s7EaboZ0Hi96BVjWkfMExQEwLMXawed9aQEuhluLlZQTEywoyWQOOLp+Y0YOqn8vw+BNfKm6hrj+icYMknDD3RtINgv7J/sqI1IObmqE7l1R8J+a1U7ftxU2nX81WyXoYx2P3CboreCSs81+5pgLKF691wscoRl9+h/gIZHO2EDT4FhfmxEFWfQHXH5C/uxq76d79B3O419R06ydMfRmzf24bxDBH64uvRi74q96L2LPShj/o9LE4Qj1TI0hxMjIO9q31CyvCcM81dAK1TR8LiOcZG+2+zaluRfma+M4grANpLJUPWDW+6UuUDkX//XbcTmbVOmF1AgMBAAECggEBAInizakcQ/vMecU0SI/3Z+xywbtmvMwRSLRZ2tzFrUe1NVZyGHfa9iNYlX3NbjngJ5S0hWyPsunP3GO5u1b9mBYMTmfDw1Rxk5v278yfsB85wBRZOLViMG70EYOT9Q7zGjipaRh9lrnMz7nuC8byaRnmwbpRes9wmdXiHKOEKNY0Aif8eu/YylFWNgk9G94HqYtOSiABRVIXKogdaQ2qNlCpifWxAXWOooxs79rRTYKAs7HaTLh9hKjlUbx07PEkoGdP1JKYSYtcTOEppR5ElpOCAINdXHyD7TJ1GagFstjc0T0skc6Ji3VrZieJycqVZoxtOaVK7WPKWGApGmklYoECgYEA2Q5tQyO7yV7WdW0C5MFqjEMYpfcAFQYKS9G12Ve5xCOSyN7oO8QO0LhXs06qJvr5f9AvLyuUmwGyiag55NiZW1upHGNFUhOIhZutqjbvqL31R2+VkTx4hW8C/mWTChbRjrCViys1f+h4fR7MuIipH2KpBERDZvpxcUtVS+SXJ9sCgYEA3/tjV4RQ5VYwlYoceAkY71XjpBrwoKKj6h6rPFUlYRs1wIdnrjWJLy8QVgvu86yW2uDohifvgq/4Zj0zK4Pz8h4acSZfRjpWvCFjfkbr4kOIVaVXpM7oWJZQIVtkl2XKo/vZqzwj6zvdpCTuJLkhexA5A+Xj5+UNrYlj33JyRO8CgYBDvVniGzPO65cYfJXrmGVNMt9tZEGVThZGhUMwek1SZhu4LsDhbhWFlBJitkkp8yeMeQdQvFQbcBMtHOA8iFCMD3YekuiebdQshmJTfeObkPUMf0l5Uxr14ahYhpC2FFsAIiH5ldmTepSnz8XqTVQipGLFHxy99akTx4PuNH/sAwKBgF+mSCcwjydQ5lCF+WBdajOS9zK2ennu2pb5X+DU77CHYS4F5QXlQN9QduZ4FCQlWQrBryrTVRn3MdnfWsHDiOKlbl9RprAj67RNgeKEQOmQM2F3yXTNEzX5guCr2co5ow7iV3MjrKchGqalSrmOAbk/FUoP24LFM1EfcfITOq8rAoGAAWnQp59O/JbPBi0njdizGruT1rb3CSOYxii3Aud4AJpkJiwaxK11RxYpT/xRDAZxkUdVtfhR4odA1GT54mEyMeWaDacNpqDOO7PvE2bqtMhVN9n7NQscDriPBKnasoXrr697985ykwgzg087C+30FYxVdQgnuAopmbjuwzhZndo=";

    const TEST_VECTOR_ENCSTRING_AES256_CBC_HMAC_WRAPPING_KEY: &str =
        "SMxxa5OuyqSzbywA8/bG9/10qICu11og/7mmn066Yt8jduf+5qD6L58sMXcDT/MPk9Hf+HDCyioDH6BbcjBOZw==";
    const TEST_VECTOR_ENCSTRING_AES256_CBC_HMAC_JSON: &str = r#"{"wrappedKey":"2.1Bf9tLM/X+8Q1EI6knvV9Q==|LM2VxYIKDmjmnPitCFFwydAC9NdoD3Lmu0bGa7z2lOF5Y6FyC6P/RMSpOq2rkwA4xxZXqjxCzAHoXnibIJ1jfI9dodvfow4SaYhdGcMGpAuouegV8ESIK85F3WKc9uJh90v7J5PtvsuS1EboLQAVaa/QKNr3wNQjzUcvA0Z0xBir/ZxYPDUaRteiG6zYH63t6KmIYlRuv7jIAJXGhJBUl4elJwNzKPHPCwsQuoLQw4J6MD/yQtXb5plUs1mKwZke3Sc/rlIuSJhDKFb9x7TGYx+xIKDq5L/ezEyxd4AL2fjqU6r30wphsCrcKB3wDh3bYAuKGhgEKwxUGJV64D6qqZ2XJJd7ZpaIFoVgy16mttJM5FJF2LSfw8dLUzLou40r4qi78pQvwzUbiiul+psUuQGyzFjvDRxmPj/F/KyuduaFWTpDcrfRRM2mWsWj8Hlq1aeTxqFuAojCoBTQTYITkPeW2rFyg0/8o32N6t4f+QfKIqrlbXpmYLaJ80CMV1bal1LeuFLwzfReW0xM3Rj6mU3Q3a/Oh5GbTC6Ec63iQm+xofEmw0N+ptZCeUq36JFWpmcmLOgTiS1240OOJylllB8weZTzq6I/VY70qlNbTZm6YWT5IguLWj/Lod74GPEK2C3rAko8OIMdg7JbmH7G8r5ky+uUPzQq2XoEJfnEvjLcZc2fUvvEANgBpV7a9WJY7lU+yxjpwvp3ks8i74d2qmZJr0cHIGVDBXjcY+vHL4+s52CvhFeOJIAGlvzLW547zkPdLhms3UanRds+D/rkD1/JNd7mzs4hS8vdCHaxnyTXFhfOMrvowxfVoRTXYkrGOFGEU/onyjL7PHhHgMmmrsLJPQp/FSv+ka3E8BawoHQB+vV02lz8BNcqFlvQy8JW+0xGlA61NQk9UCCvhGQMjkMHrKgurpDLJEJ8zv0ldSh+yKJDpSJ4YAXs+/iJFn9Jn7fl1yxvBuI8rOpcZbI574pD8dNIDol0tywdRNPYGizOSuJIBLdPw37uWlPTpODgcGVryoCsQ4q5SQhTdaT34oYk0m3AQ2fchbiJKH/fpnV+D6JO4TJQDnrZhK6UiaDLyjotHKGGPTRrLFjDVH44TXZxeyc479PsdHRc9l1WVt+r66uik98p9/mPJUyMsqiprsOwoEHVkhYKW3VDIXx2z9cgkt8dMSSrMnH1+4BWkxxSb+WnkJ7Tpw7yxdncVuMYlehVTtfcJjFwbiZ7HpFjozOUjs77P5c8bjfhqUzXb1Ya+1j0DSjZ7mDRZV/3lGhn4JiTEUNVhWpqxJJBLQf8Y/cF+dTvARtUAItO3RL+mZMWFZpwCXwKpduKqp+70NHERLXvytaiE1drEs0HXmhbXjArV4S3dyQnAvO9MH8zTodIPMIZjFgTJ0N86S1KpbhCdlR9wPxvMSb7REzN22EVShIobU2Jc59c73nHyGlrQ8hV8bdIrDzlw/ybp+3OaTkAGTIIpR3QlDHwHIExj/0kdJNSlWB5/EF2O8FGir8y23BoJnEuGMkKkoPyG4uGh8iew4mU0QiPcy32lkMBCq5RoV/B/1kiH9tTA8XRjUIbEPo/posqvA3BVCqxSgs5eIVMm0Vy/7Jw2dWn54tuDa3bsx3d/UCH+2vmpHfZ94Cndwk=|WEM+ifoci+bLSqFfad3f2jy7fBlbFRURnAWAU4Mcxds="}"#;

    const TEST_VECTOR_ENCSTRING_XAES256_GCM_WRAPPING_KEY: &str = "pQEEAlAIFEJO3Jl0RK3Oyz4BaKBxAzoAARF5BIQDBAUGIFgg7QFbs9PY0FxaggQxBES/U9zjFLNvaA/E2FepLshg0VcB";
    const TEST_VECTOR_ENCSTRING_XAES256_GCM_JSON: &str = r#"{"wrappedKey":"7.g1gdowE6AAEReQMZARwEUAgUQk7cmXRErc7LPgFooHGhBVgYxY/Y35bpLo0vqxnO7Bw+HLfBnuH+FSSPWQTRkWidst06Ud6SYKwYsBXqnRhO01akJJ4wSDk3AyFL0xjRFJcJZKCM2NgEgyGaYEEcCxhxWJNssdEYX97o/BkotkS9or7XFShX4SoTbwqsOZNgmm3rK9xrBY10NtmkAaJG0U4JjFcPK/1ddgDax2aN5HfDjE9I2h5Ya5HHa6U4iY3Njf97t4Owpmw1DOF5gQqFe2auMsgtvHdCIv+HGxionhP1hQGJLeT2smteQIpiIvGl0AHBlHxRuA4lCBqC/QDWiO5u3k/IVv7zYLl/zGxVZraQsxotcvYgCMsKISyZXaiCTd66Rhn10uicm2woaclmzdGpk0G4Ziqin1cQp2sBocwLBEiNKlZk6lqheb0Qnp+Z/t/Az2paLUKkqcN2XUsc0HkpH7G+Uj+5f64Iji7tKAQSSWaNsTFXuyKN3Yfy1JIWDWRrHdrGOp4mU0vQn5ZKWitzgsyUtvyVzs8d9mGGx037fSeJzhqFJtAMPjdVuHpBj28rT+D4a+zB2jacyTfAcJPK2afjG8/nCMx8SpEwkl0vNDyPe864Glh36FUr0qRdQ5DGhGokVip4BV7hIlKWTvNsLQemakjOxeuPCMPUsPyeYEL2A2/xX8U8e6lXcpWMPV7hSiJIIWokCf8iP/Vqkhqy16++HI36gv3F+DXDj9B2QRp50Am/NdUiinW5+JROeZBIJmBWtZj2OqXFtDaPcdA7jSyEdvStTn0h+sqp3b7kAcwNMGL5HIY5+POXxj/NJZddbvEbiBt/m/6p4vYnfeKIYL4nsawA2AdUL9/KHKF6cE5rBn308HBXMNruQhqkVMsXa8UMj3hIrw7OmaSBZ7z7GqtV/w40Y7I1HNknW/C5A+/kZROa40fesGCM5QaVpiHvrJjRrBRDuOv44r5mzVxnxDTNXpyowTrNG7OVdSU2ETTzp4joB+gBNaz2tpKcLMh/FA7TINYz6MZHTbeg+tbfLRrRv8zRRhhZ4+G03XaUajmOEtf1fk+KM/PhXBRaRKnMUOyFwaxV+vMDlcAtOJcR2jotqel/hXdFNRk4oQ+CSPpnpJCb0DZFfJUpXQhlZYzGWZXTc1DELdAPLHw6txICYy1BMQ4TvUWnYS+YepIgFt10qjp8UfmsPo9WZ7oAE3WJ/dm/V7EAWE3aLCSDEh8XlcrgXg6yzwbWec2fhGD9yMWMVuVh1Uh7IBOlNuz5sEiMz+rQlYvGIaj5uLaPtMDfIa3gxEmbzEjx1qFcVzkwrekl2s3ax5CVWR1WgW4a+KVCVC67TN0N0vviXO31KQMMTgtJ45WTRmhgGEzv3ZJ1mPytbBnTtl69aB4WT6DXKyAS3r8tvzAUK/cQut7xHxBjCdpQ/hh6IC6Vo4VDNyBvoiWm+z7fWxgWntIwmu1PoFs1hY6QE1/2B+Mm+b+ckBBYrKaAYx1tDGk64gVeVlQQw5IP5tIrkBRka3cyR6OIEVQlMf9FJlr7uShB7bVjvb1Pk1R/6USZHiHoOGm/AsyYJRzr4zSPYIxCO1rkrFzmr7UTC4phtwxUexaPXvujvBANJC6eynA/Zz32sn0CYkV9hVCI7hbG6lVVDcKhES/DAwLg0uG7tbkyKnhva0z4Cpn5JM363aRE7Ut4f+hoRQX4bP73bn+rqwJShjFnHoS5"}"#;

    const TEST_VECTOR_ENVELOPE_AES256_CBC_HMAC_AEAD_WRAPPING_KEY: &str =
        "Zoj2KTb8Fkclx3MKcYWTuvoWGttbw1pWEbSNUXLCX9hOJeMcTteety7nlzYQiQf3RhHwmEx2I+ESZbWoiyeYdw==";
    const TEST_VECTOR_ENVELOPE_AES256_CBC_HMAC_AEAD_JSON: &str = r#"{"wrappedKey":"g1gppQE6AAERegMZARwEUH/eHo7gDLBPpIaO4xhlP4I6AAE4gQQ6AAE4gCKhBVAG1idgNEC8EWvVtzZ/WvLaWQTwqn9Z/j0lc4Sr/fZhGYLykbJ0sAiCt9Wcr68s/7UjvxSs/y4zbMHQcFMU9k7WBL8fJS2U/Ek0hTWX5rPz0kBbu6sb6nr1xKvFKi9nWiTgm3LiZ15vxw1jhXJBphKaCHuIChXO4mmXRAxRyOSaLMi4qMf8A72ogGJe5PNG2vP661nII2dHwjBaU41hzqi0EKzaF1v+B6EZbML7jlyKTbQMkuOaL1+rNX0hZf/FV2ROLvBF7aF4HdnzXC4A1TC49wo8z/kAfV5HtaAOeXHzjWGMpi61BkPmcpwHaL2SkOjAORznftXbGhIHb7+cwdwJjDj5QqQ0RpyMiRsneeUIh5LPTAqB0o2SNx0GIZvKXFwrFNc8GJtz5cRrjxoM4JoqblM6S0YkjrTS37CfRPENH6Hj1B/8kIWcMajMMOiU1sK/N98q+3E37oiZAkw4+zkwUpw2Fx9Xz/ldUQ+44jhpfu78Tg299KVBAhqSFODYyMhz4VcIx6UmqeGsaiqM4ophxTrc/CcNNBo5rwmnFzHAODP122aB/Z14jiVH/+WmWX4BMLrCEuPqcsUzwjp0/QOOINWTI2mncru3INxVldpK66XA2UiUBlDACwsF2TWNodfolgOxOXz0KGCwAn6FEeaHi5O4RgUcg1fDe142F/cM+Pg+YI0kPyvdKWxywyoLBR/6qqGVh5uBxsVFK8C2pEEC3My51EyqWDWtrXT0oSiSoAtdVZuiPnUwVdTYhK5vXg17cJO1dL6UxqTp+3u6vfXgorzIoV7VHnJuCMXtVPFez2hLeHzYm+c/02XFE9/hV4Q6/gyl5NwSgyYz6s3ETw77ktvCHAhPpo3vWkWui8gEHN3iiegDzGW34SdbLKy4XVyQ9eHtBbbd2HYNjQQRC/4Jnrev1lhCMftFuhuU7WSDubM2sbn8JWigLTxz3P0fc7yZ0l1ZQogzQOfLwRG2sQu1Z93HWOWUPtGgyNej7qRaala67y10YziV1zNHNZPZ7U0mi9zD5++bIkhEyaAThPR96yuDYwmJi9yvEkabqXdwryxrQgeufnolx0/mML2iJtYUa2C8LWhHaAcZVXzeyzR2/1nHQo/HdvE966xfbVXyiwul69aZKzSsEjwA6gT+CmoWvMoqHvTlku5H2MH4vqaTxn92BwP8RJNpnwlU1Ht64dmMAj8lzsRXph4wDx9zojYUFmIjr883gTvdQ+IMRvX/PyuLdI7ZQ4nKKDTZFG+zgnp/GbUOkQgqZN+VRGh0LaXX04c8zEQQave1acYbSkNGnSl54WSODmLSyoRNyIm1FGeCAowmgiVGKkRwenEQXN4d826KG1FE/JA/X6BdMkSY0QEeJAE2CEysGqefYOb16IHh78iibURIrFObxYoTDma9NgvRsCPeTDOGlsDIZRHVMaVsfPLkMQtZvjq3L8IOKwZDcI2Yyny9ebshFTKOxZMQsnOV6tvLGClVUKulIDwILOIdt/nMdyZ4tZDdAKCYCbUT4l5mQXj+RPjQ0wdVdhkFPs7dOAV3t1z/XUQxtxWHdzM06dvBMq34+han3nnzpQ/kHEgvzRfY/05gJlxDicjwqOBgDox15tKBUzRkpQKNi0aOFl4ouMtKD9BsMRtfDvXfwZyX4jMzVmt1+RyZVk+ulQAs3lPFSivwvRM0cPk6Ml9CjDiBLVRisGP8ikkANwL3kg=="}"#;

    const TEST_VECTOR_ENVELOPE_XAES256_GCM_WRAPPING_KEY: &str = "pQEEAlBNMmYvuCR59z7TcgRliTGyAzoAARF5BIQDBAUGIFggPBYOuFiZ8UrtRWy2H+cYld9+/AgQwKpxPrGruRU/uRQB";
    const TEST_VECTOR_ENVELOPE_XAES256_GCM_JSON: &str = r#"{"wrappedKey":"g1gppQE6AAEReQMZARwEUE0yZi+4JHn3PtNyBGWJMbI6AAE4gQQ6AAE4gCKhBVgY77gEqIJsnloTg0UdfoR+v5ScJin2nFqxWQTRM+9I0moTncfFDzsP6GlxBKG4DjHqtalx1/yoaZj6fRop5TySN3zUhLDkTSLdx4TEWJjUffn6gWDyqcQs/0VvzON8yfysiI90ggwcTLjKf7vWYeV3YEEQwgWwhWkMSvjiN+tPjcZOmCsHQIin0MUJbl1avmsM9bnLLX/P8cgwOZDusGwcZs4v1GH4WDG6P/6NPpi8FF8MmA77df7qIEDDUu9D+P05GzJ1bRnmkL2syh/B4wddCxtGdLvYVc0q1PMBBVmRFzVQZx35PLMf+/o0QCYSnZqXrXpUOVlWq0Gd+t1DpRNrMAgTOUZhV7uUSzuMJhzUFmmzcb3aPgDH1ChKRZCDERyuWJyFto610odqPOYGz/+UtsCw7+bJujQBbXXMZKPzZZwvHyk7+N5h2c9S1o/DSQ5xLrrMZqN//zt82gifwkJ16CFIy+o9CUlg8sYvJDFfpQVBvw3xAeMTJaA8F38G6Art9LuD44OzgK1S/fNj3vOrsmYuX8ah5FoKlcADcaxVRNm5KSeo6c7nF1jzAkU0DvG/61/zMyHq+d7hmekHhbxG+ooo/LuKFwZpdm9x7GaIJBbYxWhc5TjRCYLWEMU7Qz8jxruRoDS/N8FICfiTHN7AAETOO0rsbcOsam8zWqnSqATzJvt2v3WqnZcOsbvFnL/GC16yamu9OHoBS2QJty6jOmH5GSWrC/khuCyt3yLMcM3TlAE7Zz6SeobVYMCgF6o1d2UJnKiE5P/mf7QraxqLBu3V0jzxWrG1Abz3v+kCb7c/2SnoF6ORLf2Tyu679EmdBIOnSEOCuToC454bdlVLGWpO5OpwwrD18KM6E/jE95836o7G0zxIOS229IpbBqRaaZr+isGnUhKyL2n45kBcAoiOSzFR0WsJQUDrpXcdNqjfIjQdbLyye6XIDz41WO7cZXQ6UbyKlHRvShh/sOE5rnbgP7wLlNdjixJ8l7j0HL0MOmWwLuXOZBVer2QeAmlP789Xv19sMDZL0dM5pKnDg8aH+qDC6uPAjlSjGws7acXLx33Nftj7liGCUCL4iRPHpdeWTXR8uQ14B8vuaIXOkojjuglEMQZVQs2FGyfH/DtYDTP8YRMVA4DBfVoukp5S5Cotg8jODckaTwQa/8BYlOsjqaaGAz009L4ZGA+E7PP2S8RRVX9iViYv0nSVoCAq/lKPHW5lB6arkQwLWaMu9+KBOnpu1iyfm2M4omw5vU3u1UcZb0QxpOu8ujd93tABflIVrrchnJHtqLvgIcrZhnNtxz5CFL2Qq+GzWUdjcZ/UeDwX6m2RqPIqRmGr/HPhrLIgQbSume4sJfcMGxjJHwXONij3t20broBE7YI51b5eEaRXdWveCugkH21VaZ1NBz7WpFLtwgLnynFmyXAFmTOj6J6J+7DCwBX9raeb6lfje5x2aP+FcQ5GUZW2AIvXMJfvWoz/1IQHwWFxXCCErE/9f0iJd3iHl7U7eB5jk3ZQiJWQRYWDfEBcLAboCy1L8Tjc+shkx3wcbQhiR5htgA7OQFQQJR9b5eMOw+XHVjLxfY++PeIsjlJvp+zgUQYDbwFlzrkRu7QLUTyP223JKz07IQY0nm27Ff8AXBXSqQdcfU+tL83FdGsS2WulZ0r5opvrF2BOf0OhgdFQ"}"#;

    fn to_b64(ctx: &KeyStoreContext<TestIds>, key: <TestIds as KeySlotIds>::Symmetric) -> String {
        B64::from(ctx.get_symmetric_key(key).unwrap().to_encoded().to_vec()).to_string()
    }

    fn to_der(ctx: &KeyStoreContext<TestIds>, key: TestPrivateKey) -> Pkcs8PrivateKeyBytes {
        ctx.get_private_key(key).unwrap().to_der().unwrap()
    }

    fn to_json(wrapped_key: LegacyCompatPrivateKeyEnvelope) -> String {
        serde_json::to_string(&WrappedKeyContainer { wrapped_key }).unwrap()
    }

    fn make_rsa_key(ctx: &mut KeyStoreContext<TestIds>) -> TestPrivateKey {
        ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1)
    }

    #[test]
    #[ignore = "Generates test vectors; run manually"]
    fn generate_test_vectors() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = make_rsa_key(&mut ctx);
        println!(
            "const TEST_VECTOR_KEY_TO_SEAL: &str = \"{}\";",
            B64::from(to_der(&ctx, key_to_seal).as_ref())
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
            let wrapped = ctx.wrap_private_key(wrapping_key, key_to_seal).unwrap();
            print_vector(
                name,
                &to_b64(&ctx, wrapping_key),
                &to_json(LegacyCompatPrivateKeyEnvelope::EncString(wrapped)),
            );
        }

        // PrivateKeyEnvelope vectors.
        for (name, algorithm) in [
            (
                "ENVELOPE_AES256_CBC_HMAC_AEAD",
                SymmetricKeyAlgorithm::Aes256CbcHmac,
            ),
            ("ENVELOPE_XAES256_GCM", SymmetricKeyAlgorithm::XAes256Gcm),
        ] {
            let wrapping_key = ctx.make_symmetric_key(algorithm);
            let sealed =
                LegacyCompatPrivateKeyEnvelope::seal(key_to_seal, wrapping_key, NAMESPACE, &ctx)
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
        let expected_der = B64::try_from(TEST_VECTOR_KEY_TO_SEAL).unwrap().into_bytes();

        let container: WrappedKeyContainer = serde_json::from_str(json).unwrap();
        assert_eq!(
            matches!(
                container.wrapped_key,
                LegacyCompatPrivateKeyEnvelope::EncString(_)
            ),
            expect_enc_string
        );

        let unsealed = container
            .wrapped_key
            .unseal(wrapping_key, NAMESPACE, &mut ctx)
            .unwrap();
        assert_eq!(to_der(&ctx, unsealed).as_ref(), expected_der.as_slice());

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

        let key_to_seal = make_rsa_key(&mut ctx);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);

        let sealed =
            LegacyCompatPrivateKeyEnvelope::seal(key_to_seal, wrapping_key, NAMESPACE, &ctx)
                .unwrap();
        assert!(matches!(
            sealed,
            LegacyCompatPrivateKeyEnvelope::PrivateKeyEnvelope(_)
        ));

        let unsealed = sealed.unseal(wrapping_key, NAMESPACE, &mut ctx).unwrap();
        assert_eq!(to_der(&ctx, unsealed), to_der(&ctx, key_to_seal));
    }

    #[test]
    fn test_seal_legacy_produces_encstring_and_unseals() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = make_rsa_key(&mut ctx);

        for algorithm in [
            SymmetricKeyAlgorithm::Aes256CbcHmac,
            SymmetricKeyAlgorithm::XAes256Gcm,
        ] {
            let wrapping_key = ctx.make_symmetric_key(algorithm);

            let sealed = LegacyCompatPrivateKeyEnvelope::seal_legacy(
                key_to_seal,
                wrapping_key,
                NAMESPACE,
                &ctx,
            )
            .unwrap();
            assert!(matches!(
                sealed,
                LegacyCompatPrivateKeyEnvelope::EncString(_)
            ));

            let unsealed = sealed.unseal(wrapping_key, NAMESPACE, &mut ctx).unwrap();
            assert_eq!(to_der(&ctx, unsealed), to_der(&ctx, key_to_seal));
        }
    }

    #[test]
    fn test_string_round_trip_preserves_variant() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = make_rsa_key(&mut ctx);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);

        let enc_string = LegacyCompatPrivateKeyEnvelope::EncString(
            ctx.wrap_private_key(wrapping_key, key_to_seal).unwrap(),
        );
        let envelope =
            LegacyCompatPrivateKeyEnvelope::seal(key_to_seal, wrapping_key, NAMESPACE, &ctx)
                .unwrap();

        for wrapped in [enc_string, envelope] {
            let is_enc_string = matches!(wrapped, LegacyCompatPrivateKeyEnvelope::EncString(_));

            let string = wrapped.to_string();
            let parsed = LegacyCompatPrivateKeyEnvelope::from_str(&string).unwrap();

            assert_eq!(
                matches!(parsed, LegacyCompatPrivateKeyEnvelope::EncString(_)),
                is_enc_string
            );
            let unsealed = parsed.unseal(wrapping_key, NAMESPACE, &mut ctx).unwrap();
            assert_eq!(to_der(&ctx, unsealed), to_der(&ctx, key_to_seal));
        }
    }

    #[test]
    fn test_encstring_wrong_key() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let key_to_seal = make_rsa_key(&mut ctx);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let wrong_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);

        let wrapped = LegacyCompatPrivateKeyEnvelope::EncString(
            ctx.wrap_private_key(wrapping_key, key_to_seal).unwrap(),
        );

        assert!(matches!(
            wrapped.unseal(wrong_key, NAMESPACE, &mut ctx),
            Err(PrivateKeyEnvelopeError::WrongKey)
        ));
    }

    #[test]
    fn test_unparseable_input_errors() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);

        // Malformed EncStrings parse laxly, round-trip unchanged, and fail on unseal.
        let unparseable = LegacyCompatPrivateKeyEnvelope::from_str("9.garbage").unwrap();
        assert_eq!(unparseable.to_string(), "9.garbage");
        assert!(
            unparseable
                .unseal(wrapping_key, NAMESPACE, &mut ctx)
                .is_err()
        );

        assert!(LegacyCompatPrivateKeyEnvelope::from_str("not base64!").is_err());
    }
}

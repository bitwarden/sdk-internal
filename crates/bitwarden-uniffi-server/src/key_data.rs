//! Validation of the key service's `data`: a JSON string holding wrapped key material.
//!
//! ```text
//!   data (JSON) --serde--> shape --SDK parsers--> key ids --agree?--> KeyIds
//! ```
//!
//! Each `data` is parsed strictly: unknown members are refused, and its `type` or `kind` picks the
//! shape. Every crypto object in it is parsed with its SDK type, and ids two objects both name
//! must be equal. Nothing is decrypted or verified; comparing the ids with stored keys is the
//! server's job.

use std::{num::NonZeroU32, str::FromStr};

use bitwarden_crypto::{
    CoseSerializable, CoseSign1Bytes, Kdf, SignedObject, SignedPublicKey, SigningNamespace,
};
use bitwarden_encoding::B64;
use serde::{Deserialize, de::DeserializeOwned};

use crate::{CryptoObjectKeyIds, CryptoParsingClient, ServerError};

/// Parses and validates key and unlock method `data`, returning the key ids it carries.
#[derive(uniffi::Object)]
pub struct KeyDataClient;

#[uniffi::export]
impl KeyDataClient {
    /// Validates a key's `data`, of the type its `type` member names.
    pub fn validate_key(&self, data: String) -> Result<KeyInfo, ServerError> {
        let parsing = CryptoParsingClient;

        match parse(&data)? {
            KeyData::PrivateKey {
                wrapped_key,
                public_key,
                signed_key,
            } => {
                let envelope = parsing.inspect_legacy_compat_symmetric_key_envelope(wrapped_key)?;
                let public = parsing.inspect_public_key(public_key)?;
                let signed_by = signed_key.map(signed_public_key_signer).transpose()?;

                // The envelope, where it names its key, holds this pair's private key.
                same(&envelope.contained_key_id, &Some(public.key_id.clone()))?;

                Ok(KeyInfo {
                    data_type: KeyDataType::PrivateKey,
                    key_ids: KeyIds {
                        key_id: Some(public.key_id),
                        signed_by_key_id: signed_by,
                        ..envelope_ids(envelope)
                    },
                })
            }
            KeyData::SigningKey {
                wrapped_key,
                public_key,
            } => {
                let envelope = parsing.inspect_legacy_compat_symmetric_key_envelope(wrapped_key)?;
                let verifying = parsing.inspect_verifying_key(public_key)?;

                same(&envelope.contained_key_id, &Some(verifying.key_id.clone()))?;

                Ok(KeyInfo {
                    data_type: KeyDataType::SigningKey,
                    key_ids: KeyIds {
                        key_id: Some(verifying.key_id),
                        ..envelope_ids(envelope)
                    },
                })
            }
            KeyData::SymmetricKey { wrapped_key } => Ok(KeyInfo {
                data_type: KeyDataType::SymmetricKey,
                key_ids: envelope_ids(
                    parsing.inspect_legacy_compat_symmetric_key_envelope(wrapped_key)?,
                ),
            }),
            KeyData::SharedKey { wrapped_key } => {
                // An RSA-encrypted key names no key.
                parsing.inspect_unsigned_shared_key(wrapped_key)?;

                Ok(KeyInfo {
                    data_type: KeyDataType::SharedKey,
                    key_ids: KeyIds::default(),
                })
            }
            KeyData::SecurityState {
                signed_security_state,
            } => {
                // SignedSecurityState lives in bitwarden-core; its wire format is a base64
                // SignedObject.
                let bytes = B64::try_from(signed_security_state.as_str())
                    .map_err(|_| ServerError::InvalidData)?;
                let signed = SignedObject::from_cose(&CoseSign1Bytes::from(&bytes))?;

                Ok(KeyInfo {
                    data_type: KeyDataType::SecurityState,
                    key_ids: KeyIds {
                        signed_by_key_id: Some(signer(&signed, SigningNamespace::SecurityState)?),
                        ..Default::default()
                    },
                })
            }
        }
    }

    /// Validates an unlock method's `data`, of the kind its `kind` member names.
    pub fn validate_unlock_method(&self, data: String) -> Result<UnlockMethodInfo, ServerError> {
        let parsing = CryptoParsingClient;

        match parse(&data)? {
            UnlockMethodData::MasterPassword(MasterPasswordData::Raw { wrapped_key, kdf }) => {
                kdf.validate()?;

                Ok(UnlockMethodInfo {
                    kind: UnlockMethodKind::MasterPassword,
                    key_ids: envelope_ids(
                        parsing.inspect_legacy_compat_symmetric_key_envelope(wrapped_key)?,
                    ),
                })
            }
            UnlockMethodData::MasterPassword(
                MasterPasswordData::PasswordProtectedKeyEnvelope { envelope },
            ) => {
                // The envelope's own KDF is not checked: the SDK reads it only to unseal.
                let ids = parsing.inspect_password_protected_key_envelope(envelope)?;

                Ok(UnlockMethodInfo {
                    kind: UnlockMethodKind::MasterPassword,
                    key_ids: KeyIds {
                        contained_key_id: ids.contained_key_id,
                        ..Default::default()
                    },
                })
            }
            UnlockMethodData::KeyConnector { wrapped_key } => Ok(UnlockMethodInfo {
                kind: UnlockMethodKind::KeyConnector,
                key_ids: envelope_ids(
                    parsing.inspect_legacy_compat_symmetric_key_envelope(wrapped_key)?,
                ),
            }),
            UnlockMethodData::Device(set) => Ok(UnlockMethodInfo {
                kind: UnlockMethodKind::Device,
                key_ids: set.validate()?,
            }),
            UnlockMethodData::Passkey(set) => Ok(UnlockMethodInfo {
                kind: UnlockMethodKind::Passkey,
                key_ids: set.validate()?,
            }),
        }
    }
}

/// What a key's `data` was.
#[derive(uniffi::Enum, Debug, PartialEq)]
pub enum KeyDataType {
    /// `legacy-compat-private-key-envelope`: a public-key encryption pair.
    PrivateKey,
    /// `legacy-compat-signing-key-envelope`: a signing pair.
    SigningKey,
    /// `legacy-compat-symmetric-key-envelope`: a symmetric key sealed by another.
    SymmetricKey,
    /// `unsigned-shared-key`: a symmetric key sealed to a public key.
    SharedKey,
    /// `signed-security-state`: a security state signed by its owner's signing key.
    SecurityState,
}

/// What an unlock method's `data` was.
#[derive(uniffi::Enum, Debug, PartialEq)]
pub enum UnlockMethodKind {
    /// `master-password`.
    MasterPassword,
    /// `key-connector`.
    KeyConnector,
    /// `device`.
    Device,
    /// `passkey`.
    Passkey,
}

/// A validated key's type and the ids its `data` carries.
#[derive(uniffi::Record, Debug, PartialEq)]
pub struct KeyInfo {
    /// The type `data` named.
    pub data_type: KeyDataType,
    /// The ids its objects carry.
    pub key_ids: KeyIds,
}

/// A validated unlock method's kind and the ids its `data` carries.
#[derive(uniffi::Record, Debug, PartialEq)]
pub struct UnlockMethodInfo {
    /// The kind `data` named.
    pub kind: UnlockMethodKind,
    /// The ids its objects carry.
    pub key_ids: KeyIds,
}

/// The key ids the objects in `data` carry, as 32 lowercase hex characters; [None] where no object
/// names one.
#[derive(uniffi::Record, Debug, Default, PartialEq)]
pub struct KeyIds {
    /// The key pair's own id: its public or verifying key's.
    pub key_id: Option<String>,
    /// The key an envelope holds.
    pub contained_key_id: Option<String>,
    /// The key that sealed it.
    pub sealed_by_key_id: Option<String>,
    /// The key that signed it.
    pub signed_by_key_id: Option<String>,
}

/// A key's `data`.
#[derive(Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum KeyData {
    #[serde(
        rename = "legacy-compat-private-key-envelope",
        rename_all = "camelCase"
    )]
    PrivateKey {
        wrapped_key: String,
        public_key: String,
        signed_key: Option<String>,
    },
    #[serde(
        rename = "legacy-compat-signing-key-envelope",
        rename_all = "camelCase"
    )]
    SigningKey {
        wrapped_key: String,
        public_key: String,
    },
    #[serde(
        rename = "legacy-compat-symmetric-key-envelope",
        rename_all = "camelCase"
    )]
    SymmetricKey { wrapped_key: String },
    #[serde(rename = "unsigned-shared-key", rename_all = "camelCase")]
    SharedKey { wrapped_key: String },
    #[serde(rename = "signed-security-state", rename_all = "camelCase")]
    SecurityState { signed_security_state: String },
}

/// An unlock method's `data`.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum UnlockMethodData {
    MasterPassword(MasterPasswordData),
    #[serde(rename_all = "camelCase")]
    KeyConnector {
        wrapped_key: String,
    },
    Device(TrustedKeySet),
    Passkey(TrustedKeySet),
}

/// Master password unlock data.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum MasterPasswordData {
    #[serde(rename_all = "camelCase")]
    Raw {
        wrapped_key: String,
        kdf: KdfData,
    },
    PasswordProtectedKeyEnvelope {
        envelope: String,
    },
}

/// A KDF and its salt; memory in MiB.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum KdfData {
    Pbkdf2 {
        iterations: NonZeroU32,
        salt: String,
    },
    Argon2id {
        iterations: NonZeroU32,
        memory: NonZeroU32,
        parallelism: NonZeroU32,
        salt: String,
    },
}

impl KdfData {
    /// Refuses an empty salt, and settings below the SDK's minimums or outside Argon2's limits.
    fn validate(self) -> Result<(), ServerError> {
        let (kdf, salt) = match self {
            KdfData::Pbkdf2 { iterations, salt } => (Kdf::PBKDF2 { iterations }, salt),
            KdfData::Argon2id {
                iterations,
                memory,
                parallelism,
                salt,
            } => (
                Kdf::Argon2id {
                    iterations,
                    memory,
                    parallelism,
                },
                salt,
            ),
        };

        if salt.is_empty() {
            return Err(ServerError::InvalidKdf);
        }

        kdf.validate().map_err(|_| ServerError::InvalidKdf)
    }
}

/// Device and passkey unlock data.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustedKeySet {
    wrapped_key: String,
    wrapped_private_key: String,
    wrapped_public_key: String,
}

impl TrustedKeySet {
    /// Checks each object's type. The user key is sealed to the set's RSA key, which names no key,
    /// so no id is returned.
    fn validate(self) -> Result<KeyIds, ServerError> {
        let parsing = CryptoParsingClient;

        parsing.inspect_unsigned_shared_key(self.wrapped_key)?;
        parsing.inspect_legacy_compat_symmetric_key_envelope(self.wrapped_private_key)?;
        parsing.inspect_enc_string(self.wrapped_public_key)?;

        Ok(KeyIds::default())
    }
}

/// Parses `data` strictly into its shape.
fn parse<T: DeserializeOwned>(data: &str) -> Result<T, ServerError> {
    serde_json::from_str(data).map_err(|_| ServerError::InvalidData)
}

/// An envelope's contained and sealing key ids.
fn envelope_ids(envelope: CryptoObjectKeyIds) -> KeyIds {
    KeyIds {
        contained_key_id: envelope.contained_key_id,
        sealed_by_key_id: envelope.encrypted_by_key_id,
        ..Default::default()
    }
}

/// The id of the key that signed a SignedPublicKey.
fn signed_public_key_signer(signed_key: String) -> Result<String, ServerError> {
    let signed_key = SignedPublicKey::from_str(&signed_key)?;

    // SignedPublicKey hides its SignedObject; re-read the same COSE bytes as one.
    let signed = SignedObject::from_cose(&CoseSign1Bytes::from(signed_key))?;

    signer(&signed, SigningNamespace::SignedPublicKey)
}

/// The id of the key that signed `signed`, refusing an object signed in another namespace, e.g. a
/// security state where a public key belongs. The signature is not verified.
fn signer(signed: &SignedObject, namespace: SigningNamespace) -> Result<String, ServerError> {
    if signed.namespace()? != namespace {
        return Err(ServerError::InvalidData);
    }

    Ok(signed.signed_by_id()?.to_string())
}

/// Refuses two ids that differ. Either missing passes: not every object names its key.
fn same(left: &Option<String>, right: &Option<String>) -> Result<(), ServerError> {
    match (left, right) {
        (Some(left), Some(right)) if left != right => Err(ServerError::KeyIdMismatch),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use bitwarden_crypto::{
        KeyStore, PrimitiveEncryptable, PublicKeyEncryptionAlgorithm, SignatureAlgorithm,
        SigningNamespace, SymmetricKeyAlgorithm, UnsignedSharedKey,
        compat::LegacyCompatSymmetricKeyEnvelope,
        key_slot_ids,
        safe::{
            PasswordProtectedKeyEnvelope, PasswordProtectedKeyEnvelopeNamespace,
            SymmetricKeyEnvelopeNamespace,
        },
    };
    use bitwarden_encoding::B64;
    use serde::Serialize;
    use serde_json::{Value, json};

    use super::*;
    use crate::ServerClient;

    key_slot_ids! {
        #[symmetric]
        pub enum TestSymmKey {
            #[local]
            Local(LocalId),
        }

        #[private]
        pub enum TestPrivateKey {
            #[local]
            Local(LocalId),
        }

        #[signing]
        pub enum TestSigningKey {
            #[local]
            Local(LocalId),
        }

        pub TestIds => TestSymmKey, TestPrivateKey, TestSigningKey;
    }

    /// Mirrors bitwarden-core's `SecurityState`.
    #[derive(Serialize)]
    struct SecurityStateStub {
        version: u64,
    }

    /// One of each crypto object, built with the SDK.
    struct Objects {
        /// COSE LegacyCompatSymmetricKeyEnvelope holding `sealed_id`, sealed by `sealing_id`.
        envelope: String,
        /// COSE EncString LegacyCompatSymmetricKeyEnvelope, sealed by `sealing_id`; names no
        /// contained key.
        enc_string_envelope: String,
        sealed_id: String,
        sealing_id: String,
        /// RSA PublicKey with id `public_key_id`.
        public_key: String,
        public_key_id: String,
        /// SignedPublicKey and SignedSecurityState, signed by `verifying_id`.
        signed_public_key: String,
        signed_security_state: String,
        verifying_key: String,
        verifying_id: String,
        shared_key: String,
        enc_string: String,
        /// PasswordProtectedKeyEnvelope holding `sealed_id`.
        password_envelope: String,
    }

    // Built once: RSA key generation and Argon2 are slow in debug builds.
    static OBJECTS: LazyLock<Objects> = LazyLock::new(|| {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let namespace = SymmetricKeyEnvelopeNamespace::OrganizationInvite;

        let sealed = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
        let sealing = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
        let private = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let signing = ctx.make_signing_key(SignatureAlgorithm::Ed25519);
        let public = ctx.get_public_key(private).expect("exists");
        let verifying = ctx.get_verifying_key(signing).expect("exists");
        let id = |key| ctx.get_symmetric_key_id(key).expect("has id").to_string();
        let (sealed_id, sealing_id) = (id(sealed), id(sealing));

        let envelope = LegacyCompatSymmetricKeyEnvelope::seal(sealed, sealing, namespace, &ctx)
            .expect("seals")
            .to_string();
        let enc_string_envelope = ctx
            .wrap_symmetric_key(sealing, sealed)
            .expect("wraps")
            .to_string();
        let signed_public_key =
            String::from(ctx.make_signed_public_key(private, signing).expect("signs"));
        let signed = ctx
            .sign(
                signing,
                &SecurityStateStub { version: 2 },
                &SigningNamespace::SecurityState,
            )
            .expect("signs");
        let shared_key = UnsignedSharedKey::encapsulate(sealed, &public, &ctx)
            .expect("encapsulates")
            .to_string();
        let password_envelope = String::from(
            PasswordProtectedKeyEnvelope::seal(
                sealed,
                "password",
                PasswordProtectedKeyEnvelopeNamespace::PinUnlock,
                &ctx,
            )
            .expect("seals"),
        );
        let enc_string = "public key"
            .encrypt(&mut ctx, sealed)
            .expect("encrypts")
            .to_string();

        Objects {
            envelope,
            enc_string_envelope,
            sealed_id,
            sealing_id,
            public_key: public.to_string(),
            public_key_id: public.key_id().expect("RSA thumbprint").to_string(),
            signed_public_key,
            signed_security_state: B64::from(signed.to_cose().as_ref()).to_string(),
            verifying_key: B64::from(verifying.to_cose().as_ref()).to_string(),
            verifying_id: verifying.key_id().to_string(),
            shared_key,
            enc_string,
            password_envelope,
        }
    });

    /// Reaches the sub-client the way bindings do, through [ServerClient].
    fn client() -> KeyDataClient {
        ServerClient::new().key_data()
    }

    fn some(id: &str) -> Option<String> {
        Some(id.to_string())
    }

    /// `value` with `member` set; [Value::Null] removes it.
    fn with(mut value: Value, member: &str, member_value: Value) -> String {
        let object = value.as_object_mut().expect("object");
        match member_value {
            Value::Null => object.remove(member),
            other => object.insert(member.to_string(), other),
        };

        value.to_string()
    }

    fn private_key() -> Value {
        let o = &*OBJECTS;
        json!({
            "type": "legacy-compat-private-key-envelope",
            "wrappedKey": o.enc_string_envelope,
            "publicKey": o.public_key,
            "signedKey": o.signed_public_key,
        })
    }

    fn signing_key() -> Value {
        let o = &*OBJECTS;
        json!({
            "type": "legacy-compat-signing-key-envelope",
            "wrappedKey": o.enc_string_envelope,
            "publicKey": o.verifying_key,
        })
    }

    fn argon2id() -> Value {
        json!({
            "type": "argon2id",
            "iterations": 3,
            "memory": 64,
            "parallelism": 4,
            "salt": "user@example.com",
        })
    }

    fn master_password(kdf: Value) -> String {
        json!({
            "kind": "master-password",
            "type": "raw",
            "wrappedKey": OBJECTS.envelope,
            "kdf": kdf,
        })
        .to_string()
    }

    fn trusted_key_set(kind: &str) -> String {
        let o = &*OBJECTS;
        json!({
            "kind": kind,
            "wrappedKey": o.shared_key,
            "wrappedPrivateKey": o.enc_string_envelope,
            "wrappedPublicKey": o.enc_string,
        })
        .to_string()
    }

    #[test]
    fn private_key_ids() {
        let o = &*OBJECTS;

        let info = client()
            .validate_key(private_key().to_string())
            .expect("valid");

        assert_eq!(
            info,
            KeyInfo {
                data_type: KeyDataType::PrivateKey,
                key_ids: KeyIds {
                    key_id: some(&o.public_key_id),
                    contained_key_id: None,
                    sealed_by_key_id: some(&o.sealing_id),
                    signed_by_key_id: some(&o.verifying_id),
                },
            }
        );
    }

    #[test]
    fn private_key_without_signed_key() {
        let data = with(private_key(), "signedKey", Value::Null);

        let info = client().validate_key(data).expect("valid");

        assert_eq!(info.key_ids.signed_by_key_id, None);
    }

    #[test]
    fn private_key_envelope_holds_another_key() {
        // The COSE envelope names the symmetric key it holds, not the pair's private key.
        let data = with(private_key(), "wrappedKey", json!(OBJECTS.envelope));

        let result = client().validate_key(data);

        assert!(matches!(result, Err(ServerError::KeyIdMismatch)));
    }

    #[test]
    fn signing_key_ids() {
        let o = &*OBJECTS;

        let info = client()
            .validate_key(signing_key().to_string())
            .expect("valid");

        assert_eq!(
            info,
            KeyInfo {
                data_type: KeyDataType::SigningKey,
                key_ids: KeyIds {
                    key_id: some(&o.verifying_id),
                    sealed_by_key_id: some(&o.sealing_id),
                    ..Default::default()
                },
            }
        );
    }

    #[test]
    fn signing_key_envelope_holds_another_key() {
        let data = with(signing_key(), "wrappedKey", json!(OBJECTS.envelope));

        let result = client().validate_key(data);

        assert!(matches!(result, Err(ServerError::KeyIdMismatch)));
    }

    #[test]
    fn symmetric_key_ids() {
        let o = &*OBJECTS;
        let data = json!({
            "type": "legacy-compat-symmetric-key-envelope",
            "wrappedKey": o.envelope,
        });

        let info = client().validate_key(data.to_string()).expect("valid");

        assert_eq!(
            info,
            KeyInfo {
                data_type: KeyDataType::SymmetricKey,
                key_ids: KeyIds {
                    contained_key_id: some(&o.sealed_id),
                    sealed_by_key_id: some(&o.sealing_id),
                    ..Default::default()
                },
            }
        );
    }

    #[test]
    fn shared_key_carries_no_ids() {
        let data = json!({ "type": "unsigned-shared-key", "wrappedKey": OBJECTS.shared_key });

        let info = client().validate_key(data.to_string()).expect("valid");

        assert_eq!(
            info,
            KeyInfo {
                data_type: KeyDataType::SharedKey,
                key_ids: KeyIds::default(),
            }
        );
    }

    #[test]
    fn security_state_ids() {
        let o = &*OBJECTS;
        let data = json!({
            "type": "signed-security-state",
            "signedSecurityState": o.signed_security_state,
        });

        let info = client().validate_key(data.to_string()).expect("valid");

        assert_eq!(
            info,
            KeyInfo {
                data_type: KeyDataType::SecurityState,
                key_ids: KeyIds {
                    signed_by_key_id: some(&o.verifying_id),
                    ..Default::default()
                },
            }
        );
    }

    #[test]
    fn key_invalid_data() {
        let o = &*OBJECTS;
        let cases = [
            "not json".to_string(),
            "[]".to_string(),
            json!({ "wrappedKey": o.envelope }).to_string(),
            json!({ "type": "unknown", "wrappedKey": o.envelope }).to_string(),
            // An unknown member rides along.
            with(private_key(), "extra", json!("x")),
            // A required member is missing.
            with(private_key(), "publicKey", Value::Null),
            // A member holds the wrong SDK type.
            with(private_key(), "publicKey", json!(o.verifying_key)),
            with(private_key(), "signedKey", json!(o.enc_string)),
            // A signed object in another namespace.
            with(private_key(), "signedKey", json!(o.signed_security_state)),
            json!({ "type": "signed-security-state", "signedSecurityState": o.signed_public_key })
                .to_string(),
            with(signing_key(), "publicKey", json!(o.public_key)),
            json!({ "type": "unsigned-shared-key", "wrappedKey": o.enc_string }).to_string(),
            json!({ "type": "signed-security-state", "signedSecurityState": "AAAA" }).to_string(),
        ];

        for data in cases {
            let result = client().validate_key(data.clone());
            assert!(matches!(result, Err(ServerError::InvalidData)), "{data}");
        }
    }

    #[test]
    fn master_password_raw_ids() {
        let o = &*OBJECTS;

        let info = client()
            .validate_unlock_method(master_password(argon2id()))
            .expect("valid");

        assert_eq!(
            info,
            UnlockMethodInfo {
                kind: UnlockMethodKind::MasterPassword,
                key_ids: KeyIds {
                    contained_key_id: some(&o.sealed_id),
                    sealed_by_key_id: some(&o.sealing_id),
                    ..Default::default()
                },
            }
        );
    }

    #[test]
    fn master_password_pbkdf2() {
        let kdf = json!({ "type": "pbkdf2", "iterations": 600000, "salt": "user@example.com" });

        let result = client().validate_unlock_method(master_password(kdf));

        assert!(result.is_ok());
    }

    #[test]
    fn master_password_invalid_kdf() {
        let cases = [
            json!({ "type": "pbkdf2", "iterations": 4999, "salt": "user@example.com" }),
            json!({ "type": "pbkdf2", "iterations": 600000, "salt": "" }),
            serde_json::from_str(&with(argon2id(), "salt", json!(""))).expect("json"),
            serde_json::from_str(&with(argon2id(), "memory", json!(15))).expect("json"),
            // Parallelism above Argon2's limit.
            serde_json::from_str(&with(argon2id(), "parallelism", json!(1 << 24))).expect("json"),
        ];

        for kdf in cases {
            let result = client().validate_unlock_method(master_password(kdf.clone()));
            assert!(matches!(result, Err(ServerError::InvalidKdf)), "{kdf}");
        }
    }

    #[test]
    fn master_password_malformed_kdf() {
        let cases = [
            // Salt beside the KDF instead of in it.
            json!({ "type": "pbkdf2", "iterations": 600000 }),
            json!({ "type": "pbkdf2", "iterations": 0, "salt": "user@example.com" }),
            json!({ "type": "scrypt", "iterations": 600000, "salt": "user@example.com" }),
            serde_json::from_str(&with(argon2id(), "extra", json!(1))).expect("json"),
        ];

        for kdf in cases {
            let result = client().validate_unlock_method(master_password(kdf.clone()));
            assert!(matches!(result, Err(ServerError::InvalidData)), "{kdf}");
        }
    }

    #[test]
    fn master_password_envelope_ids() {
        let o = &*OBJECTS;
        let data = json!({
            "kind": "master-password",
            "type": "password-protected-key-envelope",
            "envelope": o.password_envelope,
        });

        let info = client()
            .validate_unlock_method(data.to_string())
            .expect("valid");

        assert_eq!(
            info,
            UnlockMethodInfo {
                kind: UnlockMethodKind::MasterPassword,
                key_ids: KeyIds {
                    contained_key_id: some(&o.sealed_id),
                    ..Default::default()
                },
            }
        );
    }

    #[test]
    fn key_connector_ids() {
        let o = &*OBJECTS;
        let data = json!({ "kind": "key-connector", "wrappedKey": o.envelope });

        let info = client()
            .validate_unlock_method(data.to_string())
            .expect("valid");

        assert_eq!(
            info,
            UnlockMethodInfo {
                kind: UnlockMethodKind::KeyConnector,
                key_ids: KeyIds {
                    contained_key_id: some(&o.sealed_id),
                    sealed_by_key_id: some(&o.sealing_id),
                    ..Default::default()
                },
            }
        );
    }

    #[test]
    fn trusted_key_sets_carry_no_ids() {
        for (kind, expected) in [
            ("device", UnlockMethodKind::Device),
            ("passkey", UnlockMethodKind::Passkey),
        ] {
            let info = client()
                .validate_unlock_method(trusted_key_set(kind))
                .expect(kind);

            assert_eq!(
                info,
                UnlockMethodInfo {
                    kind: expected,
                    key_ids: KeyIds::default(),
                }
            );
        }
    }

    #[test]
    fn unlock_method_invalid_data() {
        let o = &*OBJECTS;
        let device: Value = serde_json::from_str(&trusted_key_set("device")).expect("json");
        let cases = [
            "not json".to_string(),
            // No kind, or an unknown one.
            json!({ "wrappedKey": o.envelope }).to_string(),
            json!({ "kind": "pin", "wrappedKey": o.envelope }).to_string(),
            // Master password without a type.
            json!({ "kind": "master-password", "wrappedKey": o.envelope }).to_string(),
            json!({ "kind": "key-connector", "wrappedKey": o.envelope, "extra": 1 }).to_string(),
            with(device.clone(), "wrappedKey", json!(o.envelope)),
            with(device.clone(), "wrappedPublicKey", json!(o.shared_key)),
            with(device, "wrappedPrivateKey", Value::Null),
            json!({
                "kind": "master-password",
                "type": "password-protected-key-envelope",
                "envelope": o.envelope,
            })
            .to_string(),
        ];

        for data in cases {
            let result = client().validate_unlock_method(data.clone());
            assert!(matches!(result, Err(ServerError::InvalidData)), "{data}");
        }
    }
}

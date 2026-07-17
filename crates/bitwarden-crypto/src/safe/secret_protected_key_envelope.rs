//! Secret protected key envelope is a cryptographic building block that allows sealing a symmetric
//! key with a high-entropy secret (a random URL-fragment secret, a derived key, random bytes, etc.)
//! of arbitrary length.
//!
//! It is implemented by using a cheap KDF (HKDF-SHA256) combined with symmetric key encryption
//! (AES-256-GCM). Unlike the [crate::safe::PasswordProtectedKeyEnvelope], which protects a
//! low-entropy secret (password, PIN) and therefore uses a hard KDF (Argon2ID, PBKDF2) to slow down
//! brute-forcing, this envelope assumes the secret is high-entropy and not brute-forceable, so a
//! cheap KDF is sufficient. The cheap KDF also natively accepts input material of arbitrary length.
//!
//! For the consumer, the output is an opaque blob that can be later unsealed with the same secret.
//! The KDF salt is contained in the envelope, and does not need to be provided for unsealing.
//!
//! Internally, the envelope is a CoseEncrypt object that uses the standardized COSE "Direct Key
//! with KDF" construction with the `direct+HKDF-SHA-256` recipient algorithm, as described in
//! [RFC 9053 §6.1.2](https://datatracker.ietf.org/doc/html/rfc9053#name-direct-key-with-kdf). The
//! random HKDF salt is placed in the single recipient's unprotected headers (the standardized
//! `salt` header parameter), and the secret is used as the input keying material. The output from
//! the KDF - "envelope key", is used directly as the content-encryption key that wraps the
//! symmetric key sealed by the envelope.
//!
//! Note: AES-GCM is used here since the CEK is locally derived, so there is no nonce re-use
//! problem.

use std::{num::TryFromIntError, str::FromStr};

use bitwarden_encoding::{B64, FromStrVisitor};
use bitwarden_sensitive_value::ExposeSensitive;
use ciborium::Value;
use coset::{CborSerializable, CoseError, Header, HeaderBuilder, iana};
use rand::Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::convert::{FromWasmAbi, IntoWasmAbi, OptionFromWasmAbi};

use crate::{
    ContentFormat, EncodedSymmetricKey, KeySlotIds, KeyStoreContext, SymmetricCryptoKey,
    cose::{
        ContentNamespace, CoseExtractError, SafeObjectNamespace, extract_bytes,
        symmetric::{
            CoseAlgorithmPolicy, CoseContentEncryptionAlgorithm, decrypt_cose, encrypt_cose,
        },
    },
    keys::KeyId,
    safe::{
        DecodeSealedKeyError, HighEntropySecret, decode_sealed_symmetric_key, extract_key_id,
        extract_single_recipient,
        helpers::{debug_fmt, set_safe_namespaces, validate_safe_namespaces},
        set_contained_key_id,
    },
};

/// The recipient algorithm used by the envelope: `direct+HKDF-SHA-256`
/// (<https://datatracker.ietf.org/doc/html/rfc9053#name-direct-key-with-kdf>).
const HKDF_ALGORITHM: coset::iana::Algorithm = iana::Algorithm::Direct_HKDF_SHA_256;
/// The standardized COSE `salt` header algorithm parameter label (-20).
const HKDF_SALT_LABEL: i64 = iana::HeaderAlgorithmParameter::Salt as i64;
/// 32 matches the SHA-256 output size (HashLen), which is the RECOMMENDED salt size for HKDF:
/// <https://datatracker.ietf.org/doc/html/rfc5869>
const ENVELOPE_HKDF_SALT_SIZE: usize = 32;
/// 32 is chosen to match the size of an AES-256-GCM key
const ENVELOPE_HKDF_OUTPUT_KEY_SIZE: usize = 32;

/// A secret-protected key envelope can seal a symmetric key, and protect it with a high-entropy
/// secret of arbitrary length.
///
/// Unlike the [crate::safe::PasswordProtectedKeyEnvelope], which is meant for low-entropy secrets
/// such as PINs and uses a compute-hard or memory-hard KDF, this envelope assumes the secret is
/// high-entropy and thus uses a cheap KDF (HKDF). The KDF salt is stored in the envelope and does
/// not have to be provided.
///
/// Internally, HKDF-SHA256 is used as the KDF and AES-256-GCM is used to encrypt the key.
#[derive(Clone)]
pub struct SecretProtectedKeyEnvelope {
    cose_encrypt: coset::CoseEncrypt,
}

impl SecretProtectedKeyEnvelope {
    /// Seals a symmetric key with a [`HighEntropySecret`], using a random salt.
    ///
    /// The secret is guaranteed to be high-entropy by the [`HighEntropySecret`] type, which the
    /// cheap KDF used here relies on, since it cannot defend a low-entropy secret against
    /// brute-forcing.
    ///
    /// This should never fail, except for memory allocation error, when running the KDF.
    pub fn seal<Ids: KeySlotIds>(
        key_to_seal: Ids::Symmetric,
        secret: &HighEntropySecret,
        namespace: SecretProtectedKeyEnvelopeNamespace,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<Self, SecretProtectedKeyEnvelopeError> {
        let key_ref = ctx
            .get_symmetric_key(key_to_seal)
            .map_err(|_| SecretProtectedKeyEnvelopeError::KeyMissing)?;
        Self::seal_ref(key_ref, secret, namespace)
    }

    /// Seals a key reference with a secret. This function is not public since callers are expected
    /// to only work with key store references.
    fn seal_ref(
        key_to_seal: &SymmetricCryptoKey,
        secret: &HighEntropySecret,
        namespace: SecretProtectedKeyEnvelopeNamespace,
    ) -> Result<Self, SecretProtectedKeyEnvelopeError> {
        Self::seal_ref_with_settings(key_to_seal, secret, &HkdfSettings::new(), namespace)
    }

    /// Seals a key reference with a secret and custom provided settings. This function is not
    /// public since callers are expected to only work with key store references.
    fn seal_ref_with_settings(
        key_to_seal: &SymmetricCryptoKey,
        secret: &HighEntropySecret,
        hkdf_settings: &HkdfSettings,
        namespace: SecretProtectedKeyEnvelopeNamespace,
    ) -> Result<Self, SecretProtectedKeyEnvelopeError> {
        // The envelope key is directly derived from the KDF and used as the key to encrypt the key
        // that should be sealed. The secret is guaranteed to be high-entropy by its type, which the
        // cheap KDF relies on for brute-force resistance. The KDF context binds the derived key to
        // the content-encryption algorithm, which is also declared in the protected header below.
        // EXPOSE: derive_cek needs the raw secret bytes to feed the KDF; the bytes never leave this
        // crate and are not logged.
        // This envelope only uses AES-256-GCM; the KDF context is bound to its IANA algorithm id.
        let cek = derive_cek(
            hkdf_settings,
            secret.as_bytes().expose_owned(),
            iana::Algorithm::A256GCM,
        )?;

        let (content_format, key_to_seal_bytes) = match key_to_seal.to_encoded_raw() {
            EncodedSymmetricKey::BitwardenLegacyKey(key_bytes) => {
                (ContentFormat::BitwardenLegacyKey, key_bytes.to_vec())
            }
            EncodedSymmetricKey::CoseKey(key_bytes) => (ContentFormat::CoseKey, key_bytes.to_vec()),
        };

        let protected_header = {
            let mut header = HeaderBuilder::from(content_format).build();
            set_contained_key_id(&mut header, key_to_seal.key_id());
            set_safe_namespaces(
                &mut header,
                SafeObjectNamespace::SecretProtectedKeyEnvelope,
                namespace,
            );
            header
        };

        // The message is constructed by placing the KDF settings in a recipient struct's
        // unprotected headers. The envelope key derived above is the content-encryption key, and
        // the content-encryption algorithm is declared in the protected header by `encrypt_cose`.
        let builder = coset::CoseEncryptBuilder::new().add_recipient(
            coset::CoseRecipientBuilder::new()
                .unprotected(hkdf_settings.into())
                .build(),
        );
        // `cek` is the fixed-size key produced by `derive_cek`, so the length check inside
        // `encrypt_cose` never trips here.
        let cose_encrypt = encrypt_cose(
            CoseContentEncryptionAlgorithm::Aes256Gcm,
            builder,
            protected_header,
            &key_to_seal_bytes,
            &cek,
        )
        .map_err(|_| SecretProtectedKeyEnvelopeError::Kdf)?;

        Ok(SecretProtectedKeyEnvelope { cose_encrypt })
    }

    /// Unseals a symmetric key from the secret-protected envelope, and stores it in the key store
    /// context.
    pub fn unseal<Ids: KeySlotIds>(
        &self,
        secret: &HighEntropySecret,
        namespace: SecretProtectedKeyEnvelopeNamespace,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Symmetric, SecretProtectedKeyEnvelopeError> {
        let key = self.unseal_ref(secret, namespace)?;
        Ok(ctx.add_local_symmetric_key(key))
    }

    fn unseal_ref(
        &self,
        secret: &HighEntropySecret,
        content_namespace: SecretProtectedKeyEnvelopeNamespace,
    ) -> Result<SymmetricCryptoKey, SecretProtectedKeyEnvelopeError> {
        // There must be exactly one recipient in the COSE Encrypt object, which contains the KDF
        // parameters.
        let recipient = extract_single_recipient(&self.cose_encrypt).map_err(|_| {
            SecretProtectedKeyEnvelopeError::Parsing("Invalid number of recipients".to_string())
        })?;

        if recipient.unprotected.alg
            != Some(coset::RegisteredLabelWithPrivate::Assigned(HKDF_ALGORITHM))
        {
            return Err(SecretProtectedKeyEnvelopeError::Parsing(
                "Unknown or unsupported KDF algorithm".to_string(),
            ));
        }

        validate_safe_namespaces(
            &self.cose_encrypt.protected.header,
            SafeObjectNamespace::SecretProtectedKeyEnvelope,
            content_namespace,
        )
        .map_err(|_| SecretProtectedKeyEnvelopeError::InvalidNamespace)?;

        let kdf_settings: HkdfSettings = (&recipient.unprotected).try_into().map_err(|_| {
            SecretProtectedKeyEnvelopeError::Parsing(
                "Invalid or missing KDF parameters".to_string(),
            )
        })?;
        // The KDF context binds the derived key to the content-encryption algorithm declared in the
        // protected header (RFC 9053 §6.1.2). `decrypt_cose` separately validates that this matches
        // the cipher, and the header is authenticated as AEAD associated data.
        let content_alg = content_encryption_algorithm(&self.cose_encrypt.protected.header)?;
        // EXPOSE: derive_cek needs the raw secret bytes to feed the KDF; the bytes never leave this
        // crate and are not logged.
        let cek = derive_cek(&kdf_settings, secret.as_bytes().expose_owned(), content_alg)?;

        // If decryption fails, the envelope-key is incorrect and thus the secret is incorrect
        // since the KDF salt is guaranteed to be correct. The envelope always declares its
        // content-encryption algorithm in the protected header, so no decryption fallback is
        // needed.
        let key_bytes = decrypt_cose(
            &self.cose_encrypt,
            CoseAlgorithmPolicy::RequireProtectedHeaderAlgorithm,
            &cek,
        )
        .map_err(|_| SecretProtectedKeyEnvelopeError::WrongSecret)?;

        decode_sealed_symmetric_key(&self.cose_encrypt.protected.header, key_bytes).map_err(|e| {
            match e {
                DecodeSealedKeyError::InvalidContentFormat => {
                    SecretProtectedKeyEnvelopeError::Parsing("Invalid content format".to_string())
                }
                DecodeSealedKeyError::UnsupportedContentFormat => {
                    SecretProtectedKeyEnvelopeError::Parsing(
                        "Unknown or unsupported content format".to_string(),
                    )
                }
                DecodeSealedKeyError::InvalidKey => {
                    SecretProtectedKeyEnvelopeError::Parsing("Failed to decode key".to_string())
                }
            }
        })
    }

    /// Re-seals the key with a new salt, and a new secret
    pub fn reseal(
        &self,
        secret: &HighEntropySecret,
        new_secret: &HighEntropySecret,
        namespace: SecretProtectedKeyEnvelopeNamespace,
    ) -> Result<Self, SecretProtectedKeyEnvelopeError> {
        let unsealed = self.unseal_ref(secret, namespace)?;
        Self::seal_ref(&unsealed, new_secret, namespace)
    }

    /// Get the key ID of the contained key, if the key ID is stored on the envelope headers.
    /// Only COSE keys have a key ID, legacy keys do not.
    pub fn contained_key_id(&self) -> Result<Option<KeyId>, SecretProtectedKeyEnvelopeError> {
        extract_key_id(&self.cose_encrypt.protected.header)
            .map_err(|_| SecretProtectedKeyEnvelopeError::Parsing("Invalid key id".to_string()))
    }
}

impl From<&SecretProtectedKeyEnvelope> for Vec<u8> {
    fn from(val: &SecretProtectedKeyEnvelope) -> Self {
        val.cose_encrypt
            .clone()
            .to_vec()
            .expect("Serialization to cose should not fail")
    }
}

impl TryFrom<&Vec<u8>> for SecretProtectedKeyEnvelope {
    type Error = CoseError;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        let cose_encrypt = coset::CoseEncrypt::from_slice(value)?;
        Ok(SecretProtectedKeyEnvelope { cose_encrypt })
    }
}

impl std::fmt::Debug for SecretProtectedKeyEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("SecretProtectedKeyEnvelope");

        debug_fmt::<SecretProtectedKeyEnvelopeNamespace>(
            &mut s,
            &self.cose_encrypt.protected.header,
        );

        if let Ok(Some(key_id)) = self.contained_key_id() {
            s.field("contained_key_id", &key_id);
        }

        s.finish()
    }
}

impl FromStr for SecretProtectedKeyEnvelope {
    type Err = SecretProtectedKeyEnvelopeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = B64::try_from(s).map_err(|_| {
            SecretProtectedKeyEnvelopeError::Parsing(
                "Invalid SecretProtectedKeyEnvelope Base64 encoding".to_string(),
            )
        })?;
        Self::try_from(&data.into_bytes()).map_err(|_| {
            SecretProtectedKeyEnvelopeError::Parsing(
                "Failed to parse SecretProtectedKeyEnvelope".to_string(),
            )
        })
    }
}

impl From<SecretProtectedKeyEnvelope> for String {
    fn from(val: SecretProtectedKeyEnvelope) -> Self {
        let serialized: Vec<u8> = (&val).into();
        B64::from(serialized).to_string()
    }
}

impl<'de> Deserialize<'de> for SecretProtectedKeyEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new())
    }
}

impl Serialize for SecretProtectedKeyEnvelope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let serialized: Vec<u8> = self.into();
        serializer.serialize_str(&B64::from(serialized).to_string())
    }
}

/// Raw HKDF settings. The salt is a fixed size, randomly generated value. Unlike a memory-hard KDF,
/// HKDF has no difficulty parameters to tune, since the input secret is assumed to be high-entropy.
struct HkdfSettings {
    alg: iana::Algorithm,
    salt: [u8; ENVELOPE_HKDF_SALT_SIZE],
}

impl HkdfSettings {
    /// Creates HKDF settings with a freshly generated random salt.
    fn new() -> Self {
        Self {
            alg: HKDF_ALGORITHM,
            salt: make_salt(),
        }
    }
}

impl From<&HkdfSettings> for Header {
    fn from(settings: &HkdfSettings) -> Header {
        HeaderBuilder::new()
            .value(HKDF_SALT_LABEL, Value::from(settings.salt.to_vec()))
            .algorithm(settings.alg)
            .build()
    }
}

impl TryInto<HkdfSettings> for &Header {
    type Error = SecretProtectedKeyEnvelopeError;

    fn try_into(self) -> Result<HkdfSettings, SecretProtectedKeyEnvelopeError> {
        Ok(HkdfSettings {
            alg: match self.alg {
                Some(coset::RegisteredLabelWithPrivate::Assigned(alg)) => alg,
                _ => {
                    return Err(SecretProtectedKeyEnvelopeError::Parsing(
                        "Missing KDF algorithm".to_string(),
                    ));
                }
            },
            salt: extract_bytes(self, HKDF_SALT_LABEL, "salt")?
                .try_into()
                .map_err(|_| {
                    SecretProtectedKeyEnvelopeError::Parsing("Invalid HKDF salt".to_string())
                })?,
        })
    }
}

fn make_salt() -> [u8; ENVELOPE_HKDF_SALT_SIZE] {
    let mut salt = [0u8; ENVELOPE_HKDF_SALT_SIZE];
    bitwarden_random::rng().fill_bytes(&mut salt);
    salt
}

/// Builds the serialized `COSE_KDF_Context` used as the HKDF `info` parameter, as required by the
/// COSE "Direct Key with KDF" construction
/// (<https://datatracker.ietf.org/doc/html/rfc9053#name-context-information-structu>):
///
/// ```cddl
/// COSE_KDF_Context = [
///     AlgorithmID : int / tstr,
///     PartyUInfo  : [ identity / nil, nonce / nil, other / nil ],
///     PartyVInfo  : [ identity / nil, nonce / nil, other / nil ],
///     SuppPubInfo : [ keyDataLength : uint, protected : empty_or_serialized_map ],
/// ]
/// ```
///
/// The context binds the derived key to the content-encryption algorithm (`alg`) and the requested
/// key length, providing domain separation. `PartyUInfo`/`PartyVInfo` are empty and `protected` is
/// the empty (zero-length) map, since no additional negotiated parameters apply.
fn kdf_context_info(alg: iana::Algorithm) -> Result<Vec<u8>, SecretProtectedKeyEnvelopeError> {
    let empty_party_info = || Value::Array(vec![Value::Null, Value::Null, Value::Null]);
    let context = Value::Array(vec![
        // AlgorithmID: the content-encryption algorithm the derived key is used for. This is the
        // algorithm declared in the protected header of the message (e.g. AES-256-GCM).
        Value::Integer((alg as i64).into()),
        empty_party_info(),
        empty_party_info(),
        Value::Array(vec![
            // keyDataLength is expressed in bits.
            Value::Integer((ENVELOPE_HKDF_OUTPUT_KEY_SIZE as u64 * 8).into()),
            // An empty protected header is the zero-length byte string.
            Value::Bytes(vec![]),
        ]),
    ]);

    let mut info = Vec::new();
    ciborium::into_writer(&context, &mut info).map_err(|_| SecretProtectedKeyEnvelopeError::Kdf)?;
    Ok(info)
}

/// Reads the content-encryption algorithm declared in the protected header. This value is used as
/// the `AlgorithmID` of the `COSE_KDF_Context`, binding the derived key to the message's declared
/// algorithm (RFC 9053 §6.1.2).
fn content_encryption_algorithm(
    header: &Header,
) -> Result<iana::Algorithm, SecretProtectedKeyEnvelopeError> {
    match header.alg {
        Some(coset::RegisteredLabelWithPrivate::Assigned(alg)) => Ok(alg),
        _ => Err(SecretProtectedKeyEnvelopeError::Parsing(
            "Missing or unsupported content encryption algorithm".to_string(),
        )),
    }
}

fn derive_cek(
    hkdf_settings: &HkdfSettings,
    secret: &[u8],
    alg: iana::Algorithm,
) -> Result<[u8; ENVELOPE_HKDF_OUTPUT_KEY_SIZE], SecretProtectedKeyEnvelopeError> {
    // COSE "Direct Key with KDF" (RFC 9053 §6.1.2) using `direct+HKDF-SHA-256`: the secret is the
    // input keying material, the random salt is the HKDF-Extract salt, and the serialized
    // COSE_KDF_Context is the HKDF-Expand info. Full HKDF (extract + expand) is used since the
    // secret can be of arbitrary length and is not required to be a uniformly random key.
    let info = kdf_context_info(alg)?;
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(&hkdf_settings.salt), secret);
    let mut key = [0u8; ENVELOPE_HKDF_OUTPUT_KEY_SIZE];
    hkdf.expand(&info, &mut key)
        .map_err(|_| SecretProtectedKeyEnvelopeError::Kdf)?;
    Ok(key)
}

/// Errors that can occur when sealing or unsealing a key with the `SecretProtectedKeyEnvelope`.
#[derive(Debug, Error)]
pub enum SecretProtectedKeyEnvelopeError {
    /// The secret provided is incorrect or the envelope was tampered with
    #[error("Wrong secret")]
    WrongSecret,
    /// The envelope could not be parsed correctly, or the KDF parameters are invalid
    #[error("Parsing error {0}")]
    Parsing(String),
    /// The KDF failed to derive a key, possibly due to invalid parameters
    #[error("Kdf error")]
    Kdf,
    /// There is no key for the provided key id in the key store
    #[error("Key missing error")]
    KeyMissing,
    /// The key store could not be written to, for example due to being read-only
    #[error("Could not write to key store")]
    KeyStore,
    /// The namespace provided in the envelope does not match any known namespaces, or is invalid
    #[error("Invalid namespace")]
    InvalidNamespace,
}

impl From<CoseExtractError> for SecretProtectedKeyEnvelopeError {
    fn from(err: CoseExtractError) -> Self {
        let CoseExtractError::MissingValue(label) = err;
        SecretProtectedKeyEnvelopeError::Parsing(format!("Missing value for {}", label))
    }
}

impl From<TryFromIntError> for SecretProtectedKeyEnvelopeError {
    fn from(err: TryFromIntError) -> Self {
        SecretProtectedKeyEnvelopeError::Parsing(format!("Invalid integer: {}", err))
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export type SecretProtectedKeyEnvelope = Tagged<string, "SecretProtectedKeyEnvelope">;
"#;

#[cfg(feature = "wasm")]
impl wasm_bindgen::describe::WasmDescribe for SecretProtectedKeyEnvelope {
    fn describe() {
        <String as wasm_bindgen::describe::WasmDescribe>::describe();
    }
}

#[cfg(feature = "wasm")]
impl FromWasmAbi for SecretProtectedKeyEnvelope {
    type Abi = <String as FromWasmAbi>::Abi;

    unsafe fn from_abi(abi: Self::Abi) -> Self {
        use wasm_bindgen::UnwrapThrowExt;
        let string = unsafe { String::from_abi(abi) };
        SecretProtectedKeyEnvelope::from_str(&string).unwrap_throw()
    }
}

#[cfg(feature = "wasm")]
impl OptionFromWasmAbi for SecretProtectedKeyEnvelope {
    fn is_none(abi: &Self::Abi) -> bool {
        <String as OptionFromWasmAbi>::is_none(abi)
    }
}

#[cfg(feature = "wasm")]
impl IntoWasmAbi for SecretProtectedKeyEnvelope {
    type Abi = <String as IntoWasmAbi>::Abi;

    fn into_abi(self) -> Self::Abi {
        let string: String = self.into();
        string.into_abi()
    }
}

#[cfg(feature = "wasm")]
impl TryFrom<wasm_bindgen::JsValue> for SecretProtectedKeyEnvelope {
    type Error = SecretProtectedKeyEnvelopeError;

    fn try_from(value: wasm_bindgen::JsValue) -> Result<Self, Self::Error> {
        let string = value.as_string().ok_or_else(|| {
            SecretProtectedKeyEnvelopeError::Parsing(
                "SecretProtectedKeyEnvelope JsValue is not a string".to_string(),
            )
        })?;
        SecretProtectedKeyEnvelope::from_str(&string)
    }
}

/// The content-layer separation namespace for secret protected key envelopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretProtectedKeyEnvelopeNamespace {
    /// Organization member invite links. The high-entropy secret is the random invite secret
    /// carried in the invite link, and the sealed key is the invite key.
    OrganizationInvite = 1,
    /// Bitwarden Desktop biometric (Windows Hello) unlock. The high-entropy secret is a PRF derived
    /// from the Windows Hello signing credential, and the sealed key is the user key.
    DesktopBiometricUnlock = 2,
    /// This namespace is only used in tests
    #[cfg(test)]
    ExampleNamespace = -1,
    /// This namespace is only used in tests
    #[cfg(test)]
    ExampleNamespace2 = -2,
}

impl SecretProtectedKeyEnvelopeNamespace {
    /// Returns the numeric value of the namespace.
    fn as_i64(&self) -> i64 {
        *self as i64
    }
}

impl TryFrom<i128> for SecretProtectedKeyEnvelopeNamespace {
    type Error = SecretProtectedKeyEnvelopeError;

    fn try_from(value: i128) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(SecretProtectedKeyEnvelopeNamespace::OrganizationInvite),
            2 => Ok(SecretProtectedKeyEnvelopeNamespace::DesktopBiometricUnlock),
            #[cfg(test)]
            -1 => Ok(SecretProtectedKeyEnvelopeNamespace::ExampleNamespace),
            #[cfg(test)]
            -2 => Ok(SecretProtectedKeyEnvelopeNamespace::ExampleNamespace2),
            _ => Err(SecretProtectedKeyEnvelopeError::InvalidNamespace),
        }
    }
}

impl TryFrom<i64> for SecretProtectedKeyEnvelopeNamespace {
    type Error = SecretProtectedKeyEnvelopeError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        Self::try_from(i128::from(value))
    }
}

impl From<SecretProtectedKeyEnvelopeNamespace> for i128 {
    fn from(val: SecretProtectedKeyEnvelopeNamespace) -> Self {
        val.as_i64().into()
    }
}

impl ContentNamespace for SecretProtectedKeyEnvelopeNamespace {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KeyStore, SymmetricKeyAlgorithm, traits::tests::TestIds};

    // A fixed, high-entropy (random) 32-byte secret. The envelope only accepts high-entropy
    // secrets, so the test vectors must be sealed with random bytes rather than ASCII text.
    const TESTVECTOR_SECRET_BYTES: &[u8] = &[
        174, 83, 45, 9, 235, 3, 186, 62, 199, 125, 198, 108, 129, 205, 24, 21, 174, 148, 88, 80,
        10, 238, 169, 66, 75, 202, 41, 201, 186, 244, 169, 67,
    ];

    fn testvector_secret() -> HighEntropySecret {
        HighEntropySecret::from_internal(TESTVECTOR_SECRET_BYTES)
    }

    // Test vectors below are generated by sealing a key with `TESTVECTOR_SECRET_BYTES` and
    // capturing the encoded key + the serialized envelope bytes (see the password-protected
    // envelope for the same approach).
    const TEST_UNSEALED_COSEKEY_ENCODED: &[u8] = &[
        165, 1, 4, 2, 80, 214, 124, 137, 200, 1, 180, 227, 27, 77, 48, 119, 198, 210, 9, 149, 144,
        3, 58, 0, 1, 17, 111, 4, 132, 3, 4, 5, 6, 32, 88, 32, 111, 105, 200, 46, 142, 185, 114,
        127, 136, 152, 153, 40, 8, 62, 120, 184, 252, 175, 210, 2, 245, 237, 175, 195, 73, 211,
        136, 23, 217, 203, 35, 10, 1,
    ];
    const TESTVECTOR_COSEKEY_ENVELOPE: &[u8] = &[
        132, 88, 40, 165, 1, 3, 3, 24, 101, 58, 0, 1, 21, 92, 80, 214, 124, 137, 200, 1, 180, 227,
        27, 77, 48, 119, 198, 210, 9, 149, 144, 58, 0, 1, 56, 129, 6, 58, 0, 1, 56, 128, 32, 161,
        5, 76, 155, 157, 246, 33, 115, 165, 158, 222, 125, 222, 199, 188, 88, 84, 132, 235, 37,
        236, 53, 75, 63, 253, 184, 134, 147, 83, 103, 87, 56, 81, 69, 202, 114, 23, 82, 25, 163,
        68, 36, 13, 104, 187, 54, 143, 167, 113, 63, 62, 88, 146, 50, 214, 209, 170, 6, 235, 122,
        44, 129, 149, 67, 213, 112, 112, 55, 51, 183, 165, 61, 168, 174, 215, 147, 110, 133, 164,
        198, 29, 177, 84, 20, 203, 8, 0, 211, 218, 226, 62, 121, 51, 129, 230, 248, 66, 170, 83,
        106, 109, 129, 131, 64, 162, 1, 41, 51, 88, 32, 123, 254, 226, 185, 81, 106, 88, 73, 109,
        191, 241, 1, 143, 230, 179, 47, 36, 100, 235, 131, 4, 180, 12, 96, 125, 91, 184, 5, 175,
        125, 188, 16, 246,
    ];
    const TEST_UNSEALED_LEGACYKEY_ENCODED: &[u8] = &[
        23, 37, 64, 225, 53, 59, 143, 179, 18, 121, 128, 120, 86, 134, 93, 166, 214, 151, 210, 46,
        240, 216, 69, 249, 247, 222, 110, 100, 185, 38, 173, 84, 202, 107, 132, 251, 144, 245, 105,
        244, 220, 93, 212, 227, 98, 208, 173, 122, 245, 78, 244, 106, 174, 124, 109, 91, 53, 119,
        96, 182, 45, 174, 206, 131,
    ];
    const TESTVECTOR_LEGACYKEY_ENVELOPE: &[u8] = &[
        132, 88, 52, 164, 1, 3, 3, 120, 34, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47,
        120, 46, 98, 105, 116, 119, 97, 114, 100, 101, 110, 46, 108, 101, 103, 97, 99, 121, 45,
        107, 101, 121, 58, 0, 1, 56, 129, 6, 58, 0, 1, 56, 128, 32, 161, 5, 76, 20, 11, 52, 107,
        155, 203, 125, 143, 165, 38, 59, 135, 88, 80, 84, 46, 227, 50, 142, 191, 103, 207, 31, 192,
        201, 215, 163, 102, 18, 93, 181, 247, 229, 12, 166, 221, 143, 98, 86, 74, 138, 12, 165, 1,
        206, 101, 240, 222, 51, 239, 216, 4, 85, 61, 212, 62, 44, 29, 1, 184, 4, 191, 189, 248,
        174, 159, 11, 133, 205, 19, 22, 28, 148, 138, 238, 136, 253, 173, 250, 69, 186, 232, 91,
        222, 238, 9, 175, 178, 214, 27, 120, 254, 212, 110, 129, 131, 64, 162, 1, 41, 51, 88, 32,
        222, 10, 249, 242, 57, 196, 223, 240, 234, 177, 19, 72, 201, 32, 1, 129, 46, 6, 76, 38,
        149, 151, 217, 94, 84, 67, 50, 107, 103, 74, 88, 72, 246,
    ];

    #[test]
    #[ignore = "Manual test to verify debug format"]
    fn test_debug() {
        let key = SymmetricCryptoKey::make_xchacha20_poly1305_key();
        let envelope = SecretProtectedKeyEnvelope::seal_ref(
            &key,
            &testvector_secret(),
            SecretProtectedKeyEnvelopeNamespace::ExampleNamespace,
        )
        .unwrap();
        println!("{:?}", envelope);
    }

    #[test]
    fn test_testvector_cosekey() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx: KeyStoreContext<'_, TestIds> = key_store.context_mut();
        let envelope = SecretProtectedKeyEnvelope::try_from(&TESTVECTOR_COSEKEY_ENVELOPE.to_vec())
            .expect("Key envelope should be valid");
        let key = envelope
            .unseal(
                &testvector_secret(),
                SecretProtectedKeyEnvelopeNamespace::ExampleNamespace,
                &mut ctx,
            )
            .expect("Unsealing should succeed");
        let unsealed_key = ctx
            .get_symmetric_key(key)
            .expect("Key should exist in the key store");
        assert_eq!(
            unsealed_key.to_encoded().to_vec(),
            TEST_UNSEALED_COSEKEY_ENCODED
        );
    }

    #[test]
    fn test_testvector_legacykey() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx: KeyStoreContext<'_, TestIds> = key_store.context_mut();
        let envelope =
            SecretProtectedKeyEnvelope::try_from(&TESTVECTOR_LEGACYKEY_ENVELOPE.to_vec())
                .expect("Key envelope should be valid");
        let key = envelope
            .unseal(
                &testvector_secret(),
                SecretProtectedKeyEnvelopeNamespace::ExampleNamespace,
                &mut ctx,
            )
            .expect("Unsealing should succeed");
        let unsealed_key = ctx
            .get_symmetric_key(key)
            .expect("Key should exist in the key store");
        assert_eq!(
            unsealed_key.to_encoded().to_vec(),
            TEST_UNSEALED_LEGACYKEY_ENCODED
        );
    }

    #[test]
    fn test_make_envelope() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx: KeyStoreContext<'_, TestIds> = key_store.context_mut();
        let test_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        let secret = testvector_secret();

        // Seal the key with a secret
        let envelope = SecretProtectedKeyEnvelope::seal(
            test_key,
            &secret,
            SecretProtectedKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();
        let serialized: Vec<u8> = (&envelope).into();

        // Unseal the key from the envelope
        let deserialized: SecretProtectedKeyEnvelope =
            SecretProtectedKeyEnvelope::try_from(&serialized).unwrap();
        let key = deserialized
            .unseal(
                &secret,
                SecretProtectedKeyEnvelopeNamespace::ExampleNamespace,
                &mut ctx,
            )
            .unwrap();

        // Verify that the unsealed key matches the original key
        let unsealed_key = ctx
            .get_symmetric_key(key)
            .expect("Key should exist in the key store");

        let key_before_sealing = ctx
            .get_symmetric_key(test_key)
            .expect("Key should exist in the key store");

        assert_eq!(unsealed_key, key_before_sealing);
    }

    #[test]
    fn test_make_envelope_legacy_key() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx: KeyStoreContext<'_, TestIds> = key_store.context_mut();
        let test_key = ctx.generate_symmetric_key();

        let secret = testvector_secret();

        // Seal the key with a secret
        let envelope = SecretProtectedKeyEnvelope::seal(
            test_key,
            &secret,
            SecretProtectedKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();
        let serialized: Vec<u8> = (&envelope).into();

        // Unseal the key from the envelope
        let deserialized: SecretProtectedKeyEnvelope =
            SecretProtectedKeyEnvelope::try_from(&serialized).unwrap();
        let key = deserialized
            .unseal(
                &secret,
                SecretProtectedKeyEnvelopeNamespace::ExampleNamespace,
                &mut ctx,
            )
            .unwrap();

        // Verify that the unsealed key matches the original key
        let unsealed_key = ctx
            .get_symmetric_key(key)
            .expect("Key should exist in the key store");

        let key_before_sealing = ctx
            .get_symmetric_key(test_key)
            .expect("Key should exist in the key store");

        assert_eq!(unsealed_key, key_before_sealing);
    }

    #[test]
    fn test_reseal_envelope() {
        let key = SymmetricCryptoKey::make_xchacha20_poly1305_key();
        let secret = testvector_secret();
        let new_secret = HighEntropySecret::make(32).unwrap();

        // Seal the key with a secret
        let envelope: SecretProtectedKeyEnvelope = SecretProtectedKeyEnvelope::seal_ref(
            &key,
            &secret,
            SecretProtectedKeyEnvelopeNamespace::ExampleNamespace,
        )
        .expect("Sealing should work");

        // Reseal
        let envelope = envelope
            .reseal(
                &secret,
                &new_secret,
                SecretProtectedKeyEnvelopeNamespace::ExampleNamespace,
            )
            .expect("Resealing should work");
        let unsealed = envelope
            .unseal_ref(
                &new_secret,
                SecretProtectedKeyEnvelopeNamespace::ExampleNamespace,
            )
            .expect("Unsealing should work");

        // Verify that the unsealed key matches the original key
        assert_eq!(unsealed, key);
    }

    #[test]
    fn test_wrong_secret() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx: KeyStoreContext<'_, TestIds> = key_store.context_mut();
        let test_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);

        let secret = testvector_secret();
        let wrong_secret = HighEntropySecret::make(32).unwrap();

        // Seal the key with a secret
        let envelope = SecretProtectedKeyEnvelope::seal(
            test_key,
            &secret,
            SecretProtectedKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        // Attempt to unseal with the wrong secret
        let deserialized: SecretProtectedKeyEnvelope =
            SecretProtectedKeyEnvelope::try_from(&(&envelope).into()).unwrap();
        assert!(matches!(
            deserialized.unseal(
                &wrong_secret,
                SecretProtectedKeyEnvelopeNamespace::ExampleNamespace,
                &mut ctx
            ),
            Err(SecretProtectedKeyEnvelopeError::WrongSecret)
        ));
    }

    #[test]
    fn test_wrong_safe_namespace() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx: KeyStoreContext<'_, TestIds> = key_store.context_mut();
        let test_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let secret = testvector_secret();

        let mut envelope = SecretProtectedKeyEnvelope::seal(
            test_key,
            &secret,
            SecretProtectedKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .expect("Seal works");

        if let Some((_, value)) = envelope
            .cose_encrypt
            .protected
            .header
            .rest
            .iter_mut()
            .find(|(label, _)| {
                matches!(label, coset::Label::Int(label_value) if *label_value == crate::cose::SAFE_OBJECT_NAMESPACE)
            })
        {
            *value = Value::Integer((SafeObjectNamespace::DataEnvelope as i64).into());
        }

        let deserialized: SecretProtectedKeyEnvelope =
            SecretProtectedKeyEnvelope::try_from(&(&envelope).into())
                .expect("Envelope should be valid");

        assert!(matches!(
            deserialized.unseal(
                &secret,
                SecretProtectedKeyEnvelopeNamespace::ExampleNamespace,
                &mut ctx,
            ),
            Err(SecretProtectedKeyEnvelopeError::InvalidNamespace)
        ));
    }

    #[test]
    fn test_key_id() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx: KeyStoreContext<'_, TestIds> = key_store.context_mut();
        let test_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let key_id = ctx.get_symmetric_key(test_key).unwrap().key_id().unwrap();

        let secret = testvector_secret();

        // Seal the key with a secret
        let envelope = SecretProtectedKeyEnvelope::seal(
            test_key,
            &secret,
            SecretProtectedKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();
        let contained_key_id = envelope.contained_key_id().unwrap();
        assert_eq!(Some(key_id), contained_key_id);
    }

    #[test]
    fn test_no_key_id() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx: KeyStoreContext<'_, TestIds> = key_store.context_mut();
        let test_key = ctx.generate_symmetric_key();

        let secret = testvector_secret();

        // Seal the key with a secret
        let envelope = SecretProtectedKeyEnvelope::seal(
            test_key,
            &secret,
            SecretProtectedKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();
        let contained_key_id = envelope.contained_key_id().unwrap();
        assert_eq!(None, contained_key_id);
    }
}

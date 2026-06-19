//! Secret protected key envelope is a cryptographic building block that allows sealing a symmetric
//! key with a high-entropy secret (a random URL-fragment secret, a derived key, random bytes, etc.)
//! of arbitrary length.
//!
//! It is implemented by using a cheap KDF (HKDF-SHA256) combined with symmetric key encryption
//! (XChaCha20-Poly1305). Unlike the [crate::safe::PasswordProtectedKeyEnvelope], which protects a
//! low-entropy secret (password, PIN) and therefore uses a hard KDF (Argon2ID, PBKDF2) to slow down
//! brute-forcing, this envelope assumes the secret is high-entropy and not brute-forceable, so a
//! cheap KDF is sufficient. The cheap KDF also natively accepts input material of arbitrary length.
//!
//! For the consumer, the output is an opaque blob that can be later unsealed with the same secret.
//! The KDF salt is contained in the envelope, and does not need to be provided for unsealing.
//!
//! Internally, the envelope is a CoseEncrypt object that uses the standardized COSE "Direct Key with
//! KDF" construction with the `direct+HKDF-SHA-256` recipient algorithm, as described in
//! [RFC 9053 §6.1.2](https://datatracker.ietf.org/doc/html/rfc9053#name-direct-key-with-kdf). The
//! random HKDF salt is placed in the single recipient's unprotected headers (the standardized `salt`
//! header parameter), and the secret is used as the input keying material. The output from the KDF -
//! "envelope key", is used directly as the content-encryption key that wraps the symmetric key
//! sealed by the envelope.

use std::{num::TryFromIntError, str::FromStr};

use bitwarden_encoding::{B64, FromStrVisitor};
use ciborium::Value;
use coset::{CborSerializable, CoseError, Header, HeaderBuilder, iana};
use rand::Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::convert::{FromWasmAbi, IntoWasmAbi, OptionFromWasmAbi};

use crate::{
    BitwardenLegacyKeyBytes, ContentFormat, CoseKeyBytes, CryptoError, EncodedSymmetricKey,
    KEY_ID_SIZE, KeySlotIds, KeyStoreContext, SymmetricCryptoKey,
    cose::{
        CONTAINED_KEY_ID, ContentNamespace, CoseExtractError, SafeObjectNamespace,
        XCHACHA20_POLY1305, extract_bytes,
    },
    keys::KeyId,
    safe::helpers::{debug_fmt, set_safe_namespaces, validate_safe_namespaces},
    xchacha20,
};

/// The recipient algorithm used by the envelope: `direct+HKDF-SHA-256`
/// (<https://datatracker.ietf.org/doc/html/rfc9053#name-direct-key-with-kdf>).
const HKDF_ALGORITHM: coset::Algorithm =
    coset::Algorithm::Assigned(iana::Algorithm::Direct_HKDF_SHA_256);
/// The standardized COSE `salt` header algorithm parameter label (-20).
const HKDF_SALT_LABEL: i64 = iana::HeaderAlgorithmParameter::Salt as i64;
/// 32 matches the SHA-256 output size (HashLen), which is the RECOMMENDED salt size for HKDF:
/// <https://datatracker.ietf.org/doc/html/rfc5869>
const ENVELOPE_HKDF_SALT_SIZE: usize = 32;
/// 32 is chosen to match the size of an XChaCha20-Poly1305 key
const ENVELOPE_HKDF_OUTPUT_KEY_SIZE: usize = 32;
/// Minimum accepted secret length in bytes. 16 bytes = 128 bits of headroom for a uniformly
/// random secret, matching the security level this envelope assumes.
const MIN_SECRET_LENGTH: usize = 16;
/// Minimum acceptable ratio of observed Shannon entropy to the maximum achievable for the given
/// length. Uniformly-random input approaches 1.0; repetitive/ASCII text falls well below.
const MIN_SECRET_ENTROPY_RATIO: f64 = 0.85;

/// A secret-protected key envelope can seal a symmetric key, and protect it with a high-entropy
/// secret of arbitrary length.
///
/// Unlike the [crate::safe::PasswordProtectedKeyEnvelope], which is meant for low-entropy secrets
/// such as PINs and uses a compute-hard or memory-hard KDF, this envelope assumes the secret is high-entropy
/// and thus uses a cheap KDF (HKDF). The KDF salt is stored in the envelope and does not have to be
/// provided.
///
/// Internally, HKDF-SHA256 is used as the KDF and XChaCha20-Poly1305 is used to encrypt the key.
#[derive(Clone)]
pub struct SecretProtectedKeyEnvelope {
    cose_encrypt: coset::CoseEncrypt,
}

impl SecretProtectedKeyEnvelope {
    /// Seals a symmetric key with a secret, using a random salt.
    ///
    /// The secret must be high-entropy: it must be at least 16 bytes long and pass a Shannon
    /// entropy check, otherwise [`SecretProtectedKeyEnvelopeError::LowEntropySecret`] is returned.
    /// This guards against accidentally protecting a key with a low-entropy secret (e.g. an ASCII
    /// password), which the cheap KDF used here cannot defend against brute-forcing.
    ///
    /// This should never fail, except for memory allocation error, when running the KDF.
    pub fn seal<Ids: KeySlotIds>(
        key_to_seal: Ids::Symmetric,
        secret: &[u8],
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
        secret: &[u8],
        namespace: SecretProtectedKeyEnvelopeNamespace,
    ) -> Result<Self, SecretProtectedKeyEnvelopeError> {
        Self::seal_ref_with_settings(key_to_seal, secret, &HkdfRawSettings::new(), namespace)
    }

    /// Seals a key reference with a secret and custom provided settings. This function is not public
    /// since callers are expected to only work with key store references.
    fn seal_ref_with_settings(
        key_to_seal: &SymmetricCryptoKey,
        secret: &[u8],
        kdf_settings: &HkdfRawSettings,
        namespace: SecretProtectedKeyEnvelopeNamespace,
    ) -> Result<Self, SecretProtectedKeyEnvelopeError> {
        // Reject low-entropy secrets, since the cheap KDF this envelope uses provides no
        // brute-force protection. This is the single chokepoint for all seal paths (`seal`,
        // `seal_ref`, and `reseal`'s new secret).
        validate_secret_entropy(secret)?;

        // Cose does not yet have a standardized way to protect a key using a secret.
        // This implements content encryption using direct encryption with a KDF derived key,
        // similar to "Direct Key with KDF" mentioned in the COSE spec. The KDF settings are
        // placed in a single recipient struct.

        // The envelope key is directly derived from the KDF and used as the key to encrypt the key
        // that should be sealed.
        let envelope_key = derive_key(kdf_settings, secret)?;

        let (content_format, key_to_seal_bytes) = match key_to_seal.to_encoded_raw() {
            EncodedSymmetricKey::BitwardenLegacyKey(key_bytes) => {
                (ContentFormat::BitwardenLegacyKey, key_bytes.to_vec())
            }
            EncodedSymmetricKey::CoseKey(key_bytes) => (ContentFormat::CoseKey, key_bytes.to_vec()),
        };

        let mut nonce = [0u8; crate::xchacha20::NONCE_SIZE];

        // The message is constructed by placing the KDF settings in a recipient struct's
        // unprotected headers. They do not need to live in the protected header, since to
        // authenticate the protected header, the settings must be correct.
        let mut cose_encrypt = coset::CoseEncryptBuilder::new()
            .add_recipient({
                let mut recipient = coset::CoseRecipientBuilder::new()
                    .unprotected(kdf_settings.into())
                    .build();
                recipient.protected.header.alg = Some(HKDF_ALGORITHM);
                recipient
            })
            .protected({
                let mut hdr = HeaderBuilder::from(content_format);
                if let Some(key_id) = key_to_seal.key_id() {
                    hdr = hdr.value(CONTAINED_KEY_ID, Value::from(Vec::from(&key_id)));
                }
                let mut header = hdr.build();
                set_safe_namespaces(
                    &mut header,
                    SafeObjectNamespace::SecretProtectedKeyEnvelope,
                    namespace,
                );
                header
            })
            .create_ciphertext(&key_to_seal_bytes, &[], |data, aad| {
                let ciphertext = xchacha20::encrypt_xchacha20_poly1305(&envelope_key, data, aad);
                nonce.copy_from_slice(&ciphertext.nonce());
                ciphertext.encrypted_bytes().to_vec()
            })
            .build();
        cose_encrypt.unprotected.iv = nonce.into();

        Ok(SecretProtectedKeyEnvelope { cose_encrypt })
    }

    /// Unseals a symmetric key from the secret-protected envelope, and stores it in the key store
    /// context.
    pub fn unseal<Ids: KeySlotIds>(
        &self,
        secret: &[u8],
        namespace: SecretProtectedKeyEnvelopeNamespace,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Symmetric, SecretProtectedKeyEnvelopeError> {
        let key = self.unseal_ref(secret, namespace)?;
        Ok(ctx.add_local_symmetric_key(key))
    }

    fn unseal_ref(
        &self,
        secret: &[u8],
        content_namespace: SecretProtectedKeyEnvelopeNamespace,
    ) -> Result<SymmetricCryptoKey, SecretProtectedKeyEnvelopeError> {
        // There must be exactly one recipient in the COSE Encrypt object, which contains the KDF
        // parameters.
        let recipient = self
            .cose_encrypt
            .recipients
            .first()
            .filter(|_| self.cose_encrypt.recipients.len() == 1)
            .ok_or_else(|| {
                SecretProtectedKeyEnvelopeError::Parsing("Invalid number of recipients".to_string())
            })?;

        if recipient.protected.header.alg != Some(HKDF_ALGORITHM) {
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

        let kdf_settings: HkdfRawSettings = (&recipient.unprotected).try_into().map_err(|_| {
            SecretProtectedKeyEnvelopeError::Parsing(
                "Invalid or missing KDF parameters".to_string(),
            )
        })?;
        let envelope_key = derive_key(&kdf_settings, secret)?;
        let nonce: [u8; crate::xchacha20::NONCE_SIZE] = self
            .cose_encrypt
            .unprotected
            .iv
            .clone()
            .try_into()
            .map_err(|_| SecretProtectedKeyEnvelopeError::Parsing("Invalid IV".to_string()))?;

        let key_bytes = self
            .cose_encrypt
            .decrypt_ciphertext(
                &[],
                || CryptoError::MissingField("ciphertext"),
                |data, aad| xchacha20::decrypt_xchacha20_poly1305(&nonce, &envelope_key, data, aad),
            )
            // If decryption fails, the envelope-key is incorrect and thus the secret is incorrect
            // since the KDF salt is guaranteed to be correct
            .map_err(|_| SecretProtectedKeyEnvelopeError::WrongSecret)?;

        SymmetricCryptoKey::try_from(
            match ContentFormat::try_from(&self.cose_encrypt.protected.header).map_err(|_| {
                SecretProtectedKeyEnvelopeError::Parsing("Invalid content format".to_string())
            })? {
                ContentFormat::BitwardenLegacyKey => EncodedSymmetricKey::BitwardenLegacyKey(
                    BitwardenLegacyKeyBytes::from(key_bytes),
                ),
                ContentFormat::CoseKey => {
                    EncodedSymmetricKey::CoseKey(CoseKeyBytes::from(key_bytes))
                }
                _ => {
                    return Err(SecretProtectedKeyEnvelopeError::Parsing(
                        "Unknown or unsupported content format".to_string(),
                    ));
                }
            },
        )
        .map_err(|_| SecretProtectedKeyEnvelopeError::Parsing("Failed to decode key".to_string()))
    }

    /// Re-seals the key with a new salt, and a new secret
    pub fn reseal(
        &self,
        secret: &[u8],
        new_secret: &[u8],
        namespace: SecretProtectedKeyEnvelopeNamespace,
    ) -> Result<Self, SecretProtectedKeyEnvelopeError> {
        let unsealed = self.unseal_ref(secret, namespace)?;
        Self::seal_ref(&unsealed, new_secret, namespace)
    }

    /// Get the key ID of the contained key, if the key ID is stored on the envelope headers.
    /// Only COSE keys have a key ID, legacy keys do not.
    pub fn contained_key_id(&self) -> Result<Option<KeyId>, SecretProtectedKeyEnvelopeError> {
        let key_id_bytes = extract_bytes(
            &self.cose_encrypt.protected.header,
            CONTAINED_KEY_ID,
            "key id",
        );

        if let Ok(bytes) = key_id_bytes {
            let key_id_array: [u8; KEY_ID_SIZE] = bytes.as_slice().try_into().map_err(|_| {
                SecretProtectedKeyEnvelopeError::Parsing("Invalid key id".to_string())
            })?;
            Ok(Some(KeyId::from(key_id_array)))
        } else {
            Ok(None)
        }
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
struct HkdfRawSettings {
    salt: [u8; ENVELOPE_HKDF_SALT_SIZE],
}

impl HkdfRawSettings {
    /// Creates HKDF settings with a freshly generated random salt.
    fn new() -> Self {
        Self { salt: make_salt() }
    }
}

impl From<&HkdfRawSettings> for Header {
    fn from(settings: &HkdfRawSettings) -> Header {
        // The salt is carried in the standardized COSE `salt` header algorithm parameter (-20).
        let mut header = HeaderBuilder::new()
            .value(HKDF_SALT_LABEL, Value::from(settings.salt.to_vec()))
            .build();
        header.alg = Some(HKDF_ALGORITHM);
        header
    }
}

impl TryInto<HkdfRawSettings> for &Header {
    type Error = SecretProtectedKeyEnvelopeError;

    fn try_into(self) -> Result<HkdfRawSettings, SecretProtectedKeyEnvelopeError> {
        Ok(HkdfRawSettings {
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
    rand::rng().fill_bytes(&mut salt);
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
/// The context binds the derived key to the content-encryption algorithm (XChaCha20-Poly1305) and
/// the requested key length, providing domain separation. `PartyUInfo`/`PartyVInfo` are empty and
/// `protected` is the empty (zero-length) map, since no additional negotiated parameters apply.
///
/// It is built directly as CBOR (rather than via coset's `CoseKdfContext`) because the AlgorithmID
/// is a private-use value, which coset's builder cannot represent.
fn kdf_context_info() -> Result<Vec<u8>, SecretProtectedKeyEnvelopeError> {
    let empty_party_info = || Value::Array(vec![Value::Null, Value::Null, Value::Null]);
    let context = Value::Array(vec![
        // AlgorithmID: the algorithm the derived key is used for - XChaCha20-Poly1305.
        Value::Integer(XCHACHA20_POLY1305.into()),
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

/// Order-0 Shannon entropy of `data` in bits per byte (0.0..=8.0).
fn shannon_entropy_bits_per_byte(data: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Rejects secrets that are too short or too low-entropy to be safely protected by the cheap
/// (non-brute-force-hardened) KDF this envelope uses.
fn validate_secret_entropy(secret: &[u8]) -> Result<(), SecretProtectedKeyEnvelopeError> {
    if secret.len() < MIN_SECRET_LENGTH {
        return Err(SecretProtectedKeyEnvelopeError::LowEntropySecret);
    }
    // The maximum achievable order-0 entropy is bounded by the number of samples when the input is
    // shorter than the 256-value byte alphabet, so compare against that ceiling rather than a fixed
    // bits-per-byte threshold.
    let max_entropy = (secret.len().min(256) as f64).log2();
    let ratio = shannon_entropy_bits_per_byte(secret) / max_entropy;
    if ratio < MIN_SECRET_ENTROPY_RATIO {
        return Err(SecretProtectedKeyEnvelopeError::LowEntropySecret);
    }
    Ok(())
}

fn derive_key(
    hkdf_settings: &HkdfRawSettings,
    secret: &[u8],
) -> Result<[u8; ENVELOPE_HKDF_OUTPUT_KEY_SIZE], SecretProtectedKeyEnvelopeError> {
    // COSE "Direct Key with KDF" (RFC 9053 §6.1.2) using `direct+HKDF-SHA-256`: the secret is the
    // input keying material, the random salt is the HKDF-Extract salt, and the serialized
    // COSE_KDF_Context is the HKDF-Expand info. Full HKDF (extract + expand) is used since the
    // secret can be of arbitrary length and is not required to be a uniformly random key.
    let info = kdf_context_info()?;
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
    /// The provided secret is too short or has insufficient entropy to be used with this envelope
    #[error("Secret has insufficient entropy")]
    LowEntropySecret,
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
    /// Neutral placeholder so the public API and example are usable. Replace with a
    /// product-specific variant when the first real consumer lands.
    ExampleUse = 1,
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
            1 => Ok(SecretProtectedKeyEnvelopeNamespace::ExampleUse),
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

    // A fixed, high-entropy (random) 32-byte secret. The envelope rejects low-entropy secrets, so
    // the test vectors must be sealed with random bytes rather than ASCII text.
    const TESTVECTOR_SECRET: &[u8] = &[
        174, 83, 45, 9, 235, 3, 186, 62, 199, 125, 198, 108, 129, 205, 24, 21, 174, 148, 88, 80,
        10, 238, 169, 66, 75, 202, 41, 201, 186, 244, 169, 67,
    ];

    // Test vectors below are generated by sealing a key with `TESTVECTOR_SECRET` and capturing the
    // encoded key + the serialized envelope bytes (see the password-protected envelope for the same
    // approach).
    const TEST_UNSEALED_COSEKEY_ENCODED: &[u8] = &[
        165, 1, 4, 2, 80, 62, 90, 33, 227, 72, 39, 219, 58, 47, 135, 117, 49, 183, 228, 4, 37, 3,
        58, 0, 1, 17, 111, 4, 132, 3, 4, 5, 6, 32, 88, 32, 28, 214, 78, 167, 40, 227, 21, 255, 161,
        175, 206, 135, 175, 143, 209, 254, 151, 184, 163, 109, 32, 70, 20, 35, 2, 120, 174, 176, 4,
        114, 239, 152, 1,
    ];
    const TESTVECTOR_COSEKEY_ENVELOPE: &[u8] = &[
        132, 88, 38, 164, 3, 24, 101, 58, 0, 1, 21, 92, 80, 62, 90, 33, 227, 72, 39, 219, 58, 47,
        135, 117, 49, 183, 228, 4, 37, 58, 0, 1, 56, 129, 6, 58, 0, 1, 56, 128, 32, 161, 5, 88, 24,
        139, 217, 106, 6, 152, 213, 1, 199, 208, 139, 94, 183, 109, 241, 39, 75, 37, 101, 92, 83,
        244, 37, 177, 61, 88, 84, 31, 2, 159, 22, 14, 203, 162, 36, 227, 66, 126, 124, 56, 128, 90,
        92, 208, 57, 36, 39, 12, 143, 185, 182, 102, 41, 176, 177, 177, 89, 18, 192, 104, 94, 1,
        206, 245, 209, 247, 130, 97, 202, 188, 86, 18, 68, 215, 203, 228, 80, 133, 88, 44, 16, 44,
        243, 211, 149, 74, 203, 33, 33, 139, 11, 51, 48, 87, 216, 104, 224, 58, 238, 33, 64, 185,
        197, 117, 85, 144, 55, 232, 125, 76, 30, 129, 131, 67, 161, 1, 41, 162, 1, 41, 51, 88, 32,
        169, 73, 114, 153, 34, 163, 97, 146, 152, 1, 122, 127, 65, 116, 232, 210, 24, 209, 22, 20,
        60, 29, 55, 36, 186, 98, 201, 12, 203, 227, 163, 30, 246,
    ];
    const TEST_UNSEALED_LEGACYKEY_ENCODED: &[u8] = &[
        179, 177, 223, 165, 47, 210, 2, 242, 254, 55, 120, 30, 21, 108, 81, 150, 134, 253, 3, 194,
        106, 179, 102, 222, 87, 210, 94, 231, 55, 174, 251, 159, 3, 244, 69, 169, 179, 233, 26, 74,
        79, 36, 22, 143, 51, 155, 131, 128, 35, 128, 195, 190, 242, 189, 118, 5, 146, 236, 58, 190,
        94, 171, 28, 38,
    ];
    const TESTVECTOR_LEGACYKEY_ENVELOPE: &[u8] = &[
        132, 88, 50, 163, 3, 120, 34, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 120,
        46, 98, 105, 116, 119, 97, 114, 100, 101, 110, 46, 108, 101, 103, 97, 99, 121, 45, 107,
        101, 121, 58, 0, 1, 56, 129, 6, 58, 0, 1, 56, 128, 32, 161, 5, 88, 24, 76, 236, 192, 23,
        48, 94, 186, 104, 122, 56, 106, 129, 105, 43, 179, 145, 103, 104, 200, 205, 188, 104, 200,
        89, 88, 80, 64, 210, 166, 213, 93, 37, 0, 43, 31, 212, 129, 17, 147, 126, 50, 37, 163, 184,
        244, 170, 148, 23, 211, 53, 159, 64, 234, 188, 136, 6, 114, 148, 87, 195, 119, 85, 249, 99,
        63, 208, 65, 48, 190, 125, 62, 112, 230, 95, 86, 29, 109, 83, 223, 95, 248, 185, 204, 236,
        193, 123, 221, 48, 245, 163, 153, 107, 27, 48, 35, 129, 162, 31, 200, 251, 103, 187, 186,
        35, 189, 56, 129, 131, 67, 161, 1, 41, 162, 1, 41, 51, 88, 32, 59, 110, 59, 130, 125, 35,
        236, 17, 174, 186, 170, 23, 207, 94, 175, 194, 231, 28, 127, 3, 252, 233, 112, 227, 128,
        244, 176, 32, 25, 121, 87, 215, 246,
    ];

    #[test]
    #[ignore = "Manual test to verify debug format"]
    fn test_debug() {
        let key = SymmetricCryptoKey::make_xchacha20_poly1305_key();
        let envelope = SecretProtectedKeyEnvelope::seal_ref(
            &key,
            TESTVECTOR_SECRET,
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
                TESTVECTOR_SECRET,
                SecretProtectedKeyEnvelopeNamespace::ExampleNamespace,
                &mut ctx,
            )
            .expect("Unsealing should succeed");
        #[allow(deprecated)]
        let unsealed_key = ctx
            .dangerous_get_symmetric_key(key)
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
                TESTVECTOR_SECRET,
                SecretProtectedKeyEnvelopeNamespace::ExampleNamespace,
                &mut ctx,
            )
            .expect("Unsealing should succeed");
        #[allow(deprecated)]
        let unsealed_key = ctx
            .dangerous_get_symmetric_key(key)
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

        let secret = TESTVECTOR_SECRET;

        // Seal the key with a secret
        let envelope = SecretProtectedKeyEnvelope::seal(
            test_key,
            secret,
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
                secret,
                SecretProtectedKeyEnvelopeNamespace::ExampleNamespace,
                &mut ctx,
            )
            .unwrap();

        // Verify that the unsealed key matches the original key
        #[allow(deprecated)]
        let unsealed_key = ctx
            .dangerous_get_symmetric_key(key)
            .expect("Key should exist in the key store");

        #[allow(deprecated)]
        let key_before_sealing = ctx
            .dangerous_get_symmetric_key(test_key)
            .expect("Key should exist in the key store");

        assert_eq!(unsealed_key, key_before_sealing);
    }

    #[test]
    fn test_make_envelope_legacy_key() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx: KeyStoreContext<'_, TestIds> = key_store.context_mut();
        let test_key = ctx.generate_symmetric_key();

        let secret = TESTVECTOR_SECRET;

        // Seal the key with a secret
        let envelope = SecretProtectedKeyEnvelope::seal(
            test_key,
            secret,
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
                secret,
                SecretProtectedKeyEnvelopeNamespace::ExampleNamespace,
                &mut ctx,
            )
            .unwrap();

        // Verify that the unsealed key matches the original key
        #[allow(deprecated)]
        let unsealed_key = ctx
            .dangerous_get_symmetric_key(key)
            .expect("Key should exist in the key store");

        #[allow(deprecated)]
        let key_before_sealing = ctx
            .dangerous_get_symmetric_key(test_key)
            .expect("Key should exist in the key store");

        assert_eq!(unsealed_key, key_before_sealing);
    }

    #[test]
    fn test_reseal_envelope() {
        let key = SymmetricCryptoKey::make_xchacha20_poly1305_key();
        let secret = TESTVECTOR_SECRET;
        // The new secret must also be high-entropy, otherwise resealing is rejected.
        let new_secret: [u8; 32] = *crate::util::generate_random_bytes();
        let new_secret = new_secret.as_slice();

        // Seal the key with a secret
        let envelope: SecretProtectedKeyEnvelope = SecretProtectedKeyEnvelope::seal_ref(
            &key,
            secret,
            SecretProtectedKeyEnvelopeNamespace::ExampleNamespace,
        )
        .expect("Sealing should work");

        // Reseal
        let envelope = envelope
            .reseal(
                secret,
                new_secret,
                SecretProtectedKeyEnvelopeNamespace::ExampleNamespace,
            )
            .expect("Resealing should work");
        let unsealed = envelope
            .unseal_ref(
                new_secret,
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

        let secret = TESTVECTOR_SECRET;
        let wrong_secret = b"wrong_secret".as_slice();

        // Seal the key with a secret
        let envelope = SecretProtectedKeyEnvelope::seal(
            test_key,
            secret,
            SecretProtectedKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();

        // Attempt to unseal with the wrong secret
        let deserialized: SecretProtectedKeyEnvelope =
            SecretProtectedKeyEnvelope::try_from(&(&envelope).into()).unwrap();
        assert!(matches!(
            deserialized.unseal(
                wrong_secret,
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
        let secret = TESTVECTOR_SECRET;

        let mut envelope = SecretProtectedKeyEnvelope::seal(
            test_key,
            secret,
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

        let a = deserialized.unseal(
            secret,
            SecretProtectedKeyEnvelopeNamespace::ExampleNamespace,
            &mut ctx,
        );
        println!("Error: {a:?}");
        assert!(matches!(
            a,
            Err(SecretProtectedKeyEnvelopeError::InvalidNamespace)
        ));
    }

    #[test]
    fn test_key_id() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx: KeyStoreContext<'_, TestIds> = key_store.context_mut();
        let test_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        #[allow(deprecated)]
        let key_id = ctx
            .dangerous_get_symmetric_key(test_key)
            .unwrap()
            .key_id()
            .unwrap();

        let secret = TESTVECTOR_SECRET;

        // Seal the key with a secret
        let envelope = SecretProtectedKeyEnvelope::seal(
            test_key,
            secret,
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

        let secret = TESTVECTOR_SECRET;

        // Seal the key with a secret
        let envelope = SecretProtectedKeyEnvelope::seal(
            test_key,
            secret,
            SecretProtectedKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();
        let contained_key_id = envelope.contained_key_id().unwrap();
        assert_eq!(None, contained_key_id);
    }

    #[test]
    fn test_entropy_rejects_ascii_text() {
        // Natural-language text, a repeated word, and a single repeated byte are all low-entropy
        // ASCII inputs that should be rejected.
        for secret in [
            b"this is a low entropy ascii secret".as_slice(),
            b"passwordpasswordpassword".as_slice(),
            b"aaaaaaaaaaaaaaaaaaaaaaaa".as_slice(),
        ] {
            assert!(
                matches!(
                    validate_secret_entropy(secret),
                    Err(SecretProtectedKeyEnvelopeError::LowEntropySecret)
                ),
                "expected {secret:?} to be rejected as low-entropy"
            );
        }
    }

    #[test]
    fn test_entropy_rejects_short_input() {
        // 15 random bytes: below the 16-byte minimum even though it is high-entropy.
        let short: [u8; 15] = *crate::util::generate_random_bytes();
        assert!(matches!(
            validate_secret_entropy(&short),
            Err(SecretProtectedKeyEnvelopeError::LowEntropySecret)
        ));
    }

    #[test]
    fn test_entropy_accepts_random() {
        let secret_16: [u8; 16] = *crate::util::generate_random_bytes();
        let secret_32: [u8; 32] = *crate::util::generate_random_bytes();
        assert!(validate_secret_entropy(&secret_16).is_ok());
        assert!(validate_secret_entropy(&secret_32).is_ok());
    }

    #[test]
    fn test_seal_rejects_low_entropy_secret() {
        let test_key = SymmetricCryptoKey::make_xchacha20_poly1305_key();
        assert!(matches!(
            SecretProtectedKeyEnvelope::seal_ref(
                &test_key,
                b"low entropy ascii secret",
                SecretProtectedKeyEnvelopeNamespace::ExampleNamespace,
            ),
            Err(SecretProtectedKeyEnvelopeError::LowEntropySecret)
        ));
    }

    #[test]
    fn test_reseal_rejects_low_entropy_new_secret() {
        let test_key = SymmetricCryptoKey::make_xchacha20_poly1305_key();
        let envelope = SecretProtectedKeyEnvelope::seal_ref(
            &test_key,
            TESTVECTOR_SECRET,
            SecretProtectedKeyEnvelopeNamespace::ExampleNamespace,
        )
        .unwrap();

        // The old (high-entropy) secret unseals fine, but the new low-entropy secret is rejected.
        assert!(matches!(
            envelope.reseal(
                TESTVECTOR_SECRET,
                b"low entropy ascii secret",
                SecretProtectedKeyEnvelopeNamespace::ExampleNamespace,
            ),
            Err(SecretProtectedKeyEnvelopeError::LowEntropySecret)
        ));
    }
}

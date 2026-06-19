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

    const TESTVECTOR_SECRET: &[u8] = b"test_secret_high_entropy_input";

    // Test vectors below are generated by sealing a key with `TESTVECTOR_SECRET` and capturing the
    // encoded key + the serialized envelope bytes (see the password-protected envelope for the same
    // approach).
    const TEST_UNSEALED_COSEKEY_ENCODED: &[u8] = &[
        165, 1, 4, 2, 80, 218, 23, 178, 40, 71, 16, 184, 21, 113, 194, 161, 47, 136, 78, 204, 250,
        3, 58, 0, 1, 17, 111, 4, 132, 3, 4, 5, 6, 32, 88, 32, 129, 175, 68, 5, 68, 77, 201, 176,
        156, 50, 76, 13, 240, 38, 114, 33, 176, 144, 180, 17, 64, 133, 23, 7, 201, 187, 23, 243,
        198, 0, 9, 10, 1,
    ];
    const TESTVECTOR_COSEKEY_ENVELOPE: &[u8] = &[
        132, 88, 38, 164, 3, 24, 101, 58, 0, 1, 21, 92, 80, 218, 23, 178, 40, 71, 16, 184, 21, 113,
        194, 161, 47, 136, 78, 204, 250, 58, 0, 1, 56, 129, 6, 58, 0, 1, 56, 128, 32, 161, 5, 88,
        24, 91, 185, 12, 161, 189, 223, 205, 159, 18, 142, 96, 243, 9, 236, 142, 54, 50, 72, 108,
        188, 17, 27, 79, 3, 88, 84, 47, 133, 84, 37, 221, 253, 10, 179, 219, 169, 135, 180, 16, 41,
        57, 248, 40, 130, 237, 232, 7, 246, 231, 185, 102, 38, 19, 159, 188, 56, 41, 25, 69, 90,
        172, 179, 35, 205, 180, 210, 179, 107, 253, 179, 105, 229, 64, 202, 191, 183, 81, 55, 142,
        199, 206, 188, 19, 145, 42, 1, 225, 15, 117, 169, 198, 118, 39, 61, 101, 130, 21, 202, 110,
        223, 42, 244, 251, 52, 234, 124, 29, 123, 143, 137, 129, 131, 67, 161, 1, 41, 162, 1, 41,
        51, 88, 32, 63, 32, 217, 75, 117, 216, 50, 96, 58, 57, 36, 248, 81, 88, 18, 119, 181, 86,
        58, 183, 122, 248, 28, 172, 97, 196, 20, 146, 40, 18, 154, 89, 246,
    ];
    const TEST_UNSEALED_LEGACYKEY_ENCODED: &[u8] = &[
        153, 101, 137, 87, 78, 134, 191, 255, 171, 66, 222, 154, 26, 92, 118, 185, 171, 64, 106,
        175, 110, 32, 117, 66, 98, 64, 187, 182, 217, 25, 129, 213, 19, 28, 21, 62, 86, 250, 40,
        76, 166, 40, 185, 124, 117, 54, 213, 181, 196, 181, 30, 203, 253, 31, 204, 166, 106, 183,
        5, 254, 202, 181, 222, 226,
    ];
    const TESTVECTOR_LEGACYKEY_ENVELOPE: &[u8] = &[
        132, 88, 50, 163, 3, 120, 34, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 120,
        46, 98, 105, 116, 119, 97, 114, 100, 101, 110, 46, 108, 101, 103, 97, 99, 121, 45, 107,
        101, 121, 58, 0, 1, 56, 129, 6, 58, 0, 1, 56, 128, 32, 161, 5, 88, 24, 218, 229, 71, 67,
        82, 231, 218, 98, 154, 205, 34, 227, 30, 214, 50, 3, 230, 192, 198, 216, 193, 43, 102, 40,
        88, 80, 66, 60, 14, 119, 56, 108, 21, 117, 237, 16, 158, 151, 83, 198, 183, 27, 114, 137,
        88, 248, 11, 90, 145, 103, 94, 212, 12, 137, 14, 87, 120, 178, 80, 155, 220, 174, 177, 253,
        173, 142, 112, 152, 101, 102, 198, 109, 122, 116, 163, 253, 185, 248, 236, 222, 164, 25,
        156, 84, 162, 2, 146, 22, 50, 188, 192, 243, 58, 131, 211, 41, 216, 46, 6, 121, 217, 191,
        111, 87, 248, 215, 129, 131, 67, 161, 1, 41, 162, 1, 41, 51, 88, 32, 80, 146, 52, 74, 44,
        75, 138, 80, 46, 91, 106, 99, 58, 92, 31, 83, 0, 1, 32, 224, 82, 227, 90, 237, 86, 14, 141,
        246, 207, 54, 123, 22, 246,
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
        let new_secret = b"new_test_secret".as_slice();

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
}

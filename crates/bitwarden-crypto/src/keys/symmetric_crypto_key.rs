use std::{pin::Pin, str::FromStr};

use bitwarden_encoding::{B64, FromStrVisitor};
use ciborium::{Value, value::Integer};
use coset::{
    CborSerializable, RegisteredLabelWithPrivate,
    iana::{EnumI64, KeyOperation, KeyParameter, KeyType, SymmetricKeyParameter},
};
use hybrid_array::Array;
use rand::RngExt;
#[cfg(test)]
use rand::SeedableRng;
#[cfg(test)]
use rand_chacha::ChaChaRng;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use sha2::Digest;
use subtle::{Choice, ConstantTimeEq};
use typenum::{U32, U64};
#[cfg(feature = "wasm")]
use wasm_bindgen::convert::{FromWasmAbi, IntoWasmAbi, OptionFromWasmAbi};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    key_encryptable::CryptoKey,
    key_id::{KEY_ID_SIZE, KeyId},
};
use crate::{
    BitwardenLegacyKeyBytes, ContentFormat, CoseKeyBytes, CoseKeyThumbprint, CryptoError, cose,
    cose::{
        CoseKeyThumbprintExt, symmetric::CoseContentEncryptionAlgorithm,
        thumbprint_from_required_params,
    },
    error::EncodingError,
};

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export type SymmetricKey = Tagged<string, "SymmetricKey">;
"#;

#[cfg(feature = "wasm")]
bitwarden_ffi::impl_wire_object!(SymmetricCryptoKey);

#[cfg(feature = "wasm")]
impl wasm_bindgen::describe::WasmDescribe for SymmetricCryptoKey {
    fn describe() {
        <String as wasm_bindgen::describe::WasmDescribe>::describe();
    }
}

#[cfg(feature = "wasm")]
impl FromWasmAbi for SymmetricCryptoKey {
    type Abi = <String as FromWasmAbi>::Abi;

    unsafe fn from_abi(abi: Self::Abi) -> Self {
        use wasm_bindgen::UnwrapThrowExt;
        let string = unsafe { String::from_abi(abi) };
        let b64 = B64::try_from(string).unwrap_throw();
        SymmetricCryptoKey::try_from(b64).unwrap_throw()
    }
}

#[cfg(feature = "wasm")]
impl OptionFromWasmAbi for SymmetricCryptoKey {
    fn is_none(abi: &Self::Abi) -> bool {
        <String as OptionFromWasmAbi>::is_none(abi)
    }
}

#[cfg(feature = "wasm")]
impl IntoWasmAbi for SymmetricCryptoKey {
    type Abi = <String as IntoWasmAbi>::Abi;

    fn into_abi(self) -> Self::Abi {
        let string: String = self.to_base64().to_string();
        string.into_abi()
    }
}

#[cfg(feature = "wasm")]
impl TryFrom<wasm_bindgen::JsValue> for SymmetricCryptoKey {
    type Error = CryptoError;

    fn try_from(value: wasm_bindgen::JsValue) -> Result<Self, Self::Error> {
        let string = value.as_string().ok_or(CryptoError::InvalidKey)?;
        Self::try_from(string)
    }
}

/// The symmetric key algorithm to use when generating a new symmetric key.
#[derive(Debug, PartialEq)]
pub enum SymmetricKeyAlgorithm {
    /// Used for V1 user keys and data encryption
    Aes256CbcHmac,
    /// Used by old PIN PasswordProtectedKeyEnvelope
    XChaCha20Poly1305,
    /// FIPS-approved AEAD.
    /// Used as content encryption key in:
    /// [`DataEnvelope`](crate::safe::DataEnvelope)s.
    /// [`PasswordProtectedKeyEnvelope`](crate::safe::PasswordProtectedKeyEnvelope)
    ///
    /// May not be used for multi-device scoped keys such as the user-key or organization-key
    Aes256Gcm,
    /// Extended-nonce AES-256-GCM. Used for V2 user keys and as a general-purpose
    /// encryption/wrapping key.
    XAes256Gcm,
}

/// [Aes256CbcKey] is a symmetric encryption key, consisting of one 256-bit key,
/// used to decrypt legacy type 0 enc strings. The data is not authenticated
/// so this should be used with caution, and removed where possible.
#[derive(ZeroizeOnDrop, Clone)]
pub struct Aes256CbcKey {
    /// Uses a pinned heap data structure, as noted in [Pinned heap data][crate#pinned-heap-data]
    pub(crate) enc_key: Pin<Box<Array<u8, U32>>>,
}

impl ConstantTimeEq for Aes256CbcKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.enc_key.ct_eq(&other.enc_key)
    }
}

impl PartialEq for Aes256CbcKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

/// The size of the encryption half of an [`Aes256CbcHmacKey`].
pub(crate) const AES256_CBC_HMAC_ENC_KEY_SIZE: usize = 32;
/// The size of the MAC half of an [`Aes256CbcHmacKey`].
pub(crate) const AES256_CBC_HMAC_MAC_KEY_SIZE: usize = 32;
/// The size of the composite `enc_key || mac_key` buffer of an [`Aes256CbcHmacKey`].
pub(crate) const AES256_CBC_HMAC_KEY_SIZE: usize =
    AES256_CBC_HMAC_ENC_KEY_SIZE + AES256_CBC_HMAC_MAC_KEY_SIZE;

/// [Aes256CbcHmacKey] is a symmetric encryption key consisting
/// of two 256-bit keys, one for encryption and one for MAC
#[derive(ZeroizeOnDrop, Clone)]
pub struct Aes256CbcHmacKey {
    /// The encryption and MAC keys, stored contiguously as `enc_key || mac_key`.
    ///
    /// They are kept in one buffer rather than two so that the 64-byte composite form — the layout
    /// used by the byte serialization, by the
    /// [`Aes256CbcHmacSha256Aead`](crate::hazmat::symmetric_encryption::Aes256CbcHmacSha256Aead)
    /// cipher, and by this key's COSE key view — can be borrowed instead of copied. Use
    /// [`Aes256CbcHmacKey::enc_key`] and [`Aes256CbcHmacKey::mac_key`] for zero-copy views of the
    /// individual halves.
    ///
    /// Uses a pinned heap data structure, as noted in [Pinned heap data][crate#pinned-heap-data]
    pub(crate) key: Pin<Box<Array<u8, U64>>>,
}

impl ConstantTimeEq for Aes256CbcHmacKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.key.ct_eq(&other.key)
    }
}

impl Aes256CbcHmacKey {
    /// Builds a key from its two halves.
    pub(crate) fn new(
        enc_key: &[u8; AES256_CBC_HMAC_ENC_KEY_SIZE],
        mac_key: &[u8; AES256_CBC_HMAC_MAC_KEY_SIZE],
    ) -> Self {
        let mut key = Box::pin(Array::<u8, U64>::default());
        let (enc, mac) = key.split_at_mut(AES256_CBC_HMAC_ENC_KEY_SIZE);
        enc.copy_from_slice(enc_key);
        mac.copy_from_slice(mac_key);
        Self { key }
    }

    /// Returns the 64-byte composite key (`enc_key || mac_key`), which is the layout expected by
    /// the [`Aes256CbcHmacSha256`](crate::hazmat::symmetric_encryption::Aes256CbcHmacSha256) and
    /// [`Aes256CbcHmacSha256Aead`](crate::hazmat::symmetric_encryption::Aes256CbcHmacSha256Aead)
    /// ciphers.
    pub(crate) fn as_composite_key(&self) -> &[u8; AES256_CBC_HMAC_KEY_SIZE] {
        &self.key.0
    }

    /// Returns the composite key as a slice. This is also this key's legacy byte serialization.
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.key.as_slice()
    }

    /// Returns a zero-copy view of the 256-bit encryption key.
    pub(crate) fn enc_key(&self) -> &[u8; AES256_CBC_HMAC_ENC_KEY_SIZE] {
        let (enc_key, _) = self.key.split_at(AES256_CBC_HMAC_ENC_KEY_SIZE);
        enc_key
            .try_into()
            .expect("first half of a 64-byte key is always 32 bytes")
    }

    /// Returns a zero-copy view of the 256-bit MAC key.
    pub(crate) fn mac_key(&self) -> &[u8; AES256_CBC_HMAC_MAC_KEY_SIZE] {
        let (_, mac_key) = self.key.split_at(AES256_CBC_HMAC_ENC_KEY_SIZE);
        mac_key
            .try_into()
            .expect("second half of a 64-byte key is always 32 bytes")
    }

    /// Returns the key ID of this key.
    ///
    /// Unlike the other COSE key types, this key has no field to store a key ID in — it is
    /// serialized as a bare 64-byte blob with no `kid`. The ID is therefore *derived*: it is the
    /// key's own [RFC 9679](https://www.rfc-editor.org/rfc/rfc9679) thumbprint truncated to
    /// [`KEY_ID_SIZE`] bytes. Two keys with identical key material consequently share an ID, and a
    /// key's ID is stable across serialization round-trips.
    pub(crate) fn key_id(&self) -> KeyId {
        let thumbprint = symmetric_key_thumbprint(self.as_slice());
        let mut key_id = [0u8; KEY_ID_SIZE];
        key_id.copy_from_slice(&thumbprint.as_bytes()[..KEY_ID_SIZE]);
        KeyId::from(key_id)
    }
}

/// Computes the [RFC 9679](https://www.rfc-editor.org/rfc/rfc9679) thumbprint of a COSE `Symmetric`
/// key with the given `k` bytes. `kty` and `k` are the only required parameters for this key type,
/// so they are the only ones hashed.
fn symmetric_key_thumbprint(key_bytes: &[u8]) -> CoseKeyThumbprint {
    thumbprint_from_required_params(vec![
        (
            KeyParameter::Kty.to_i64(),
            Value::Integer(Integer::from(KeyType::Symmetric.to_i64())),
        ),
        (
            SymmetricKeyParameter::K.to_i64(),
            Value::Bytes(key_bytes.to_vec()),
        ),
    ])
}

impl PartialEq for Aes256CbcHmacKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

/// [XChaCha20Poly1305Key] is a symmetric encryption key consisting
/// of one 256-bit key, and contains a key id. In contrast to the
/// [Aes256CbcKey] and [Aes256CbcHmacKey], this key type is used to create
/// CoseEncrypt0 messages.
#[derive(Zeroize, Clone)]
pub struct XChaCha20Poly1305Key {
    pub(crate) key_id: KeyId,
    pub(crate) enc_key: Pin<Box<Array<u8, U32>>>,
    /// Controls which key operations are allowed with this key. Note: Only checking decrypt is
    /// implemented right now, and implementing is tracked here <https://bitwarden.atlassian.net/browse/PM-27513>.
    /// Further, disabling decrypt will also disable unwrap. The only use-case so far is
    /// `DataEnvelope`.
    #[zeroize(skip)]
    pub(crate) supported_operations: Vec<KeyOperation>,
}

impl XChaCha20Poly1305Key {
    /// Creates a new XChaCha20Poly1305Key with a securely sampled cryptographic key and key id.
    pub fn make() -> Self {
        let mut rng = bitwarden_random::rng();
        let mut enc_key = Box::pin(Array::<u8, U32>::default());
        rng.fill(enc_key.as_mut_slice());
        let key_id = KeyId::make();

        Self {
            enc_key,
            key_id,
            supported_operations: vec![
                KeyOperation::Decrypt,
                KeyOperation::Encrypt,
                KeyOperation::WrapKey,
                KeyOperation::UnwrapKey,
            ],
        }
    }
}

impl ConstantTimeEq for XChaCha20Poly1305Key {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.enc_key.ct_eq(&other.enc_key) & self.key_id.ct_eq(&other.key_id)
    }
}

impl PartialEq for XChaCha20Poly1305Key {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

/// [Aes256GcmKey] is a symmetric AEAD key consisting of one 256-bit key
#[derive(Zeroize, Clone)]
pub struct Aes256GcmKey {
    pub(crate) key_id: KeyId,
    pub(crate) enc_key: Pin<Box<Array<u8, U32>>>,
    /// Controls which key operations are allowed with this key. See
    /// [`XChaCha20Poly1305Key::supported_operations`].
    #[zeroize(skip)]
    pub(crate) supported_operations: Vec<KeyOperation>,
}

impl Aes256GcmKey {
    /// Creates a new Aes256GcmKey with a securely sampled cryptographic key and key id.
    pub fn make() -> Self {
        let mut rng = bitwarden_random::rng();
        let mut enc_key = Box::pin(Array::<u8, U32>::default());
        rng.fill(enc_key.as_mut_slice());
        let key_id = KeyId::make();

        Self {
            enc_key,
            key_id,
            supported_operations: vec![
                KeyOperation::Decrypt,
                KeyOperation::Encrypt,
                KeyOperation::WrapKey,
                KeyOperation::UnwrapKey,
            ],
        }
    }

    pub(crate) fn disable_key_operation(&mut self, op: KeyOperation) -> &mut Self {
        self.supported_operations.retain(|k| *k != op);
        self
    }
}

impl ConstantTimeEq for Aes256GcmKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.enc_key.ct_eq(&other.enc_key) & self.key_id.ct_eq(&other.key_id)
    }
}

impl PartialEq for Aes256GcmKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

/// An XAES-256-GCM key consisting of one 256-bit key and a key ID.
#[derive(Zeroize, Clone)]
pub struct XAes256GcmKey {
    pub(crate) key_id: KeyId,
    pub(crate) enc_key: Pin<Box<Array<u8, U32>>>,
    #[zeroize(skip)]
    pub(crate) supported_operations: Vec<KeyOperation>,
}

impl XAes256GcmKey {
    /// Creates a new XAES-256-GCM key with securely sampled key bytes and key ID.
    pub fn make() -> Self {
        let mut rng = bitwarden_random::rng();
        let mut enc_key = Box::pin(Array::<u8, U32>::default());
        rng.fill(enc_key.as_mut_slice());

        Self {
            key_id: KeyId::make(),
            enc_key,
            supported_operations: vec![
                KeyOperation::Decrypt,
                KeyOperation::Encrypt,
                KeyOperation::WrapKey,
                KeyOperation::UnwrapKey,
            ],
        }
    }
}

impl ConstantTimeEq for XAes256GcmKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.enc_key.ct_eq(&other.enc_key) & self.key_id.ct_eq(&other.key_id)
    }
}

impl PartialEq for XAes256GcmKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

/// A borrowed view over a symmetric key that can be used as a COSE content-encryption key.
pub(crate) enum CoseKeyView<'a> {
    Aes256Gcm(&'a Aes256GcmKey),
    XChaCha20Poly1305(&'a XChaCha20Poly1305Key),
    XAes256Gcm(&'a XAes256GcmKey),
    Aes256CbcHmac(&'a Aes256CbcHmacKey),
}

impl CoseKeyView<'_> {
    /// Returns the key ID of the viewed key.
    ///
    /// This is returned by value rather than by reference because
    /// [`CoseKeyView::Aes256CbcHmac`] derives its ID from the key material instead of storing one;
    /// see [`Aes256CbcHmacKey::key_id`].
    pub(crate) fn key_id(&self) -> KeyId {
        match self {
            CoseKeyView::Aes256Gcm(k) => k.key_id.clone(),
            CoseKeyView::XChaCha20Poly1305(k) => k.key_id.clone(),
            CoseKeyView::XAes256Gcm(k) => k.key_id.clone(),
            CoseKeyView::Aes256CbcHmac(k) => k.key_id(),
        }
    }

    /// Returns the key material in the layout the corresponding [`algorithm`](Self::algorithm)
    /// expects as its content-encryption key.
    pub(crate) fn key_bytes(&self) -> &[u8] {
        match self {
            CoseKeyView::Aes256Gcm(k) => k.enc_key.as_slice(),
            CoseKeyView::XChaCha20Poly1305(k) => k.enc_key.as_slice(),
            CoseKeyView::XAes256Gcm(k) => k.enc_key.as_slice(),
            CoseKeyView::Aes256CbcHmac(k) => k.as_slice(),
        }
    }

    pub(crate) fn algorithm(&self) -> CoseContentEncryptionAlgorithm {
        match self {
            CoseKeyView::Aes256Gcm(_) => CoseContentEncryptionAlgorithm::Aes256Gcm,
            CoseKeyView::XChaCha20Poly1305(_) => CoseContentEncryptionAlgorithm::XChaCha20Poly1305,
            CoseKeyView::XAes256Gcm(_) => CoseContentEncryptionAlgorithm::XAes256Gcm,
            CoseKeyView::Aes256CbcHmac(_) => CoseContentEncryptionAlgorithm::Aes256CbcHmacSha256,
        }
    }
}

/// A symmetric encryption key. Used to encrypt and decrypt [`EncString`](crate::EncString)
#[derive(ZeroizeOnDrop, Clone)]
pub enum SymmetricCryptoKey {
    #[allow(missing_docs)]
    Aes256CbcKey(Aes256CbcKey),
    #[allow(missing_docs)]
    Aes256CbcHmacKey(Aes256CbcHmacKey),
    /// Data encrypted by XChaCha20Poly1305Key keys has type
    /// [`Cose_Encrypt0_B64`](crate::EncString::Cose_Encrypt0_B64)
    XChaCha20Poly1305Key(XChaCha20Poly1305Key),
    /// FIPS-approved AES-256-GCM key, used as the content-encryption key for FIPS
    /// [`DataEnvelope`](crate::safe::DataEnvelope)s. Encoded as a COSE key.
    Aes256GcmKey(Aes256GcmKey),
    /// Extended-nonce AES-256-GCM key. Encoded as a COSE key and used with
    /// type-7 EncStrings.
    XAes256GcmKey(XAes256GcmKey),
}

impl SymmetricCryptoKey {
    // enc type 0 old static format
    const AES256_CBC_KEY_LEN: usize = 32;
    // enc type 2 old static format
    const AES256_CBC_HMAC_KEY_LEN: usize = 64;

    /// Generate a new random AES256_CBC [SymmetricCryptoKey]
    ///
    /// WARNING: This function should only be used with a proper cryptographic RNG. If you do not
    /// have a good reason for using this function, use
    /// [SymmetricCryptoKey::make_aes256_cbc_hmac_key] instead.
    pub(crate) fn make_aes256_cbc_hmac_key_internal(mut rng: impl rand::CryptoRng) -> Self {
        let mut key = Box::pin(Array::<u8, U64>::default());
        // Drawn as two separate 32-byte fills, matching the order and sizes used before the two
        // halves shared one buffer, so seeded generation stays byte-for-byte identical.
        let (enc_key, mac_key) = key.split_at_mut(AES256_CBC_HMAC_ENC_KEY_SIZE);
        rng.fill(enc_key);
        rng.fill(mac_key);

        Self::Aes256CbcHmacKey(Aes256CbcHmacKey { key })
    }

    /// Make a new [SymmetricCryptoKey] for the specified algorithm
    pub fn make(algorithm: SymmetricKeyAlgorithm) -> Self {
        match algorithm {
            SymmetricKeyAlgorithm::Aes256CbcHmac => Self::make_aes256_cbc_hmac_key(),
            SymmetricKeyAlgorithm::XChaCha20Poly1305 => Self::make_xchacha20_poly1305_key(),
            SymmetricKeyAlgorithm::Aes256Gcm => Self::Aes256GcmKey(Aes256GcmKey::make()),
            SymmetricKeyAlgorithm::XAes256Gcm => Self::XAes256GcmKey(XAes256GcmKey::make()),
        }
    }

    /// Generate a new random AES256_CBC_HMAC [SymmetricCryptoKey]
    pub(crate) fn make_aes256_cbc_hmac_key() -> Self {
        let rng = bitwarden_random::rng();
        Self::make_aes256_cbc_hmac_key_internal(rng)
    }

    /// Generate a new random XChaCha20Poly1305 [SymmetricCryptoKey]
    pub(crate) fn make_xchacha20_poly1305_key() -> Self {
        let mut rng = bitwarden_random::rng();
        let mut enc_key = Box::pin(Array::<u8, U32>::default());
        rng.fill(enc_key.as_mut_slice());
        Self::XChaCha20Poly1305Key(XChaCha20Poly1305Key {
            enc_key,
            key_id: KeyId::make(),
            supported_operations: vec![
                KeyOperation::Decrypt,
                KeyOperation::Encrypt,
                KeyOperation::WrapKey,
                KeyOperation::UnwrapKey,
            ],
        })
    }

    /// Encodes the key to a byte array representation, that is separated by size.
    /// [SymmetricCryptoKey::Aes256CbcHmacKey] and [SymmetricCryptoKey::Aes256CbcKey] are
    /// encoded as 64 and 32 bytes respectively. COSE-serialized variants are encoded as at least
    /// 65 bytes using padding.
    ///
    /// This can be used for storage and transmission in the old byte array format.
    /// When the wrapping key is a COSE key, and the wrapped key is a COSE key, then this should
    /// not use the byte representation but instead use the COSE key representation.
    pub fn to_encoded(&self) -> BitwardenLegacyKeyBytes {
        let encoded_key = self.to_encoded_raw();
        match encoded_key {
            EncodedSymmetricKey::BitwardenLegacyKey(_) => {
                let encoded_key: Vec<u8> = encoded_key.into();
                BitwardenLegacyKeyBytes::from(encoded_key)
            }
            EncodedSymmetricKey::CoseKey(_) => {
                let mut encoded_key: Vec<u8> = encoded_key.into();
                pad_key(&mut encoded_key, (Self::AES256_CBC_HMAC_KEY_LEN + 1) as u8); // This is less than 255
                BitwardenLegacyKeyBytes::from(encoded_key)
            }
        }
    }

    /// Generate a new random [SymmetricCryptoKey] for unit tests. Note: DO NOT USE THIS
    /// IN PRODUCTION CODE.
    #[cfg(test)]
    pub fn generate_seeded_for_unit_tests(seed: &str) -> Self {
        // Keep this separate from the other generate function to not break test vectors.
        let mut seeded_rng = ChaChaRng::from_seed(sha2::Sha256::digest(seed.as_bytes()).into());
        let mut key = Box::pin(Array::<u8, U64>::default());
        // Two separate 32-byte fills, as above, so the generated key is unchanged.
        let (enc_key, mac_key) = key.split_at_mut(AES256_CBC_HMAC_ENC_KEY_SIZE);
        seeded_rng.fill(enc_key);
        seeded_rng.fill(mac_key);

        SymmetricCryptoKey::Aes256CbcHmacKey(Aes256CbcHmacKey { key })
    }

    /// Creates the byte representation of the key, without any padding. This should not
    /// be used directly for creating serialized key representations, instead,
    /// [SymmetricCryptoKey::to_encoded] should be used.
    ///
    /// [SymmetricCryptoKey::Aes256CbcHmacKey] and
    /// [SymmetricCryptoKey::Aes256CbcKey] are encoded as 64 and 32 byte arrays
    /// respectively, representing the key bytes directly. XChaCha20-Poly1305,
    /// AES-256-GCM, and XAES-256-GCM keys are encoded as serialized COSE keys.
    /// A COSE key can be directly encrypted with a COSE key content format or
    /// represented as a byte array. When represented as a byte array, the array
    /// is padded to be larger than the byte array representation of the other
    /// aforementioned key types.
    pub(crate) fn to_encoded_raw(&self) -> EncodedSymmetricKey {
        match self {
            Self::Aes256CbcKey(key) => {
                EncodedSymmetricKey::BitwardenLegacyKey(key.enc_key.to_vec().into())
            }
            Self::Aes256CbcHmacKey(key) => {
                EncodedSymmetricKey::BitwardenLegacyKey(key.as_slice().to_vec().into())
            }
            Self::XChaCha20Poly1305Key(key) => {
                let builder = coset::CoseKeyBuilder::new_symmetric_key(key.enc_key.to_vec());
                let mut cose_key = builder.key_id((&key.key_id).into());
                for op in &key.supported_operations {
                    cose_key = cose_key.add_key_op(*op);
                }
                let mut cose_key = cose_key.build();
                cose_key.alg = Some(RegisteredLabelWithPrivate::PrivateUse(
                    cose::XCHACHA20_POLY1305,
                ));
                EncodedSymmetricKey::CoseKey(
                    cose_key
                        .to_vec()
                        .expect("cose key serialization should not fail")
                        .into(),
                )
            }
            Self::XAes256GcmKey(key) => {
                let builder = coset::CoseKeyBuilder::new_symmetric_key(key.enc_key.to_vec());
                let mut cose_key = builder.key_id((&key.key_id).into());
                for op in &key.supported_operations {
                    cose_key = cose_key.add_key_op(*op);
                }
                let mut cose_key = cose_key.build();
                cose_key.alg = Some(RegisteredLabelWithPrivate::PrivateUse(cose::XAES_256_GCM));
                EncodedSymmetricKey::CoseKey(
                    cose_key
                        .to_vec()
                        .expect("cose key serialization should not fail")
                        .into(),
                )
            }
            Self::Aes256GcmKey(key) => {
                let builder = coset::CoseKeyBuilder::new_symmetric_key(key.enc_key.to_vec());
                let mut cose_key = builder.key_id((&key.key_id).into());
                for op in &key.supported_operations {
                    cose_key = cose_key.add_key_op(*op);
                }
                let mut cose_key = cose_key.build();
                cose_key.alg = Some(RegisteredLabelWithPrivate::Assigned(
                    coset::iana::Algorithm::A256GCM,
                ));
                EncodedSymmetricKey::CoseKey(
                    cose_key
                        .to_vec()
                        .expect("cose key serialization should not fail")
                        .into(),
                )
            }
        }
    }

    pub(crate) fn try_from_cose(serialized_key: &[u8]) -> Result<Self, CryptoError> {
        let cose_key =
            coset::CoseKey::from_slice(serialized_key).map_err(|_| CryptoError::InvalidKey)?;
        let key = SymmetricCryptoKey::try_from(&cose_key)?;
        Ok(key)
    }

    #[allow(missing_docs)]
    pub fn to_base64(&self) -> B64 {
        B64::from(self.to_encoded().as_ref())
    }

    /// Returns the key ID of the key, if it has one. Every authenticated key variant has a key ID;
    /// only the unauthenticated [`SymmetricCryptoKey::Aes256CbcKey`] does not.
    ///
    /// [`SymmetricCryptoKey::Aes256CbcHmacKey`] has no field to store a key ID in, and derives one
    /// from its key material instead: its RFC 9679 thumbprint, truncated to the key ID length. Two
    /// such keys with identical key material therefore share an ID.
    pub fn key_id(&self) -> Option<KeyId> {
        match self {
            Self::Aes256CbcKey(_) => None,
            Self::Aes256CbcHmacKey(key) => Some(key.key_id()),
            Self::XChaCha20Poly1305Key(key) => Some(key.key_id.clone()),
            Self::Aes256GcmKey(key) => Some(key.key_id.clone()),
            Self::XAes256GcmKey(key) => Some(key.key_id.clone()),
        }
    }

    /// Returns a [`CoseKeyView`] for every symmetric key variant usable as a COSE
    /// content-encryption key. Only the unauthenticated [`SymmetricCryptoKey::Aes256CbcKey`]
    /// returns `None`.
    pub(crate) fn as_cose_key_view(&self) -> Option<CoseKeyView<'_>> {
        match self {
            Self::Aes256GcmKey(k) => Some(CoseKeyView::Aes256Gcm(k)),
            Self::XChaCha20Poly1305Key(k) => Some(CoseKeyView::XChaCha20Poly1305(k)),
            Self::XAes256GcmKey(k) => Some(CoseKeyView::XAes256Gcm(k)),
            Self::Aes256CbcHmacKey(k) => Some(CoseKeyView::Aes256CbcHmac(k)),
            Self::Aes256CbcKey(_) => None,
        }
    }
}

impl CoseKeyThumbprintExt for SymmetricCryptoKey {
    /// Computes the RFC 9679 thumbprint of this symmetric key.
    ///
    /// Returns an error for the unauthenticated legacy AES-CBC key, which is not representable as
    /// a COSE key.
    fn thumbprint(&self) -> Result<CoseKeyThumbprint, CryptoError> {
        let view = self
            .as_cose_key_view()
            .ok_or(EncodingError::UnsupportedValue(
                "unauthenticated AES-CBC keys are not COSE keys and have no thumbprint",
            ))?;
        Ok(symmetric_key_thumbprint(view.key_bytes()))
    }
}

impl ConstantTimeEq for SymmetricCryptoKey {
    /// Note: This is constant time with respect to comparing two keys of the same type, but not
    /// constant type with respect to the fact that different keys are compared. If two types of
    /// different keys are compared, then this does have different timing.
    fn ct_eq(&self, other: &SymmetricCryptoKey) -> Choice {
        use SymmetricCryptoKey::*;
        match (self, other) {
            (Aes256CbcKey(a), Aes256CbcKey(b)) => a.ct_eq(b),
            (Aes256CbcKey(_), _) => Choice::from(0),

            (Aes256CbcHmacKey(a), Aes256CbcHmacKey(b)) => a.ct_eq(b),
            (Aes256CbcHmacKey(_), _) => Choice::from(0),

            (XChaCha20Poly1305Key(a), XChaCha20Poly1305Key(b)) => a.ct_eq(b),
            (XChaCha20Poly1305Key(_), _) => Choice::from(0),

            (Aes256GcmKey(a), Aes256GcmKey(b)) => a.ct_eq(b),
            (Aes256GcmKey(_), _) => Choice::from(0),

            (XAes256GcmKey(a), XAes256GcmKey(b)) => a.ct_eq(b),
            (XAes256GcmKey(_), _) => Choice::from(0),
        }
    }
}

impl PartialEq for SymmetricCryptoKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl TryFrom<String> for SymmetricCryptoKey {
    type Error = CryptoError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let bytes = B64::try_from(value).map_err(|_| CryptoError::InvalidKey)?;
        Self::try_from(bytes)
    }
}

impl TryFrom<B64> for SymmetricCryptoKey {
    type Error = CryptoError;

    fn try_from(value: B64) -> Result<Self, Self::Error> {
        Self::try_from(&BitwardenLegacyKeyBytes::from(&value))
    }
}

impl TryFrom<&BitwardenLegacyKeyBytes> for SymmetricCryptoKey {
    type Error = CryptoError;

    fn try_from(value: &BitwardenLegacyKeyBytes) -> Result<Self, Self::Error> {
        let slice = value.as_ref();

        // Raw byte serialized keys are either 32, 64, or more bytes long. If they are 32/64, they
        // are the raw serializations of the AES256-CBC, and AES256-CBC-HMAC keys. If they
        // are longer, they are COSE keys. The COSE keys are padded to the minimum length of
        // 65 bytes, when serialized to raw byte arrays.

        if slice.len() == Self::AES256_CBC_HMAC_KEY_LEN || slice.len() == Self::AES256_CBC_KEY_LEN {
            Self::try_from(EncodedSymmetricKey::BitwardenLegacyKey(value.clone()))
        } else if slice.len() > Self::AES256_CBC_HMAC_KEY_LEN {
            let unpadded_value = unpad_key(slice)?;
            Ok(Self::try_from_cose(unpadded_value)?)
        } else {
            Err(CryptoError::InvalidKeyLen)
        }
    }
}

impl TryFrom<EncodedSymmetricKey> for SymmetricCryptoKey {
    type Error = CryptoError;

    fn try_from(value: EncodedSymmetricKey) -> Result<Self, Self::Error> {
        match value {
            EncodedSymmetricKey::BitwardenLegacyKey(key)
                if key.as_ref().len() == Self::AES256_CBC_KEY_LEN =>
            {
                let mut enc_key = Box::pin(Array::<u8, U32>::default());
                enc_key.copy_from_slice(&key.as_ref()[..Self::AES256_CBC_KEY_LEN]);
                Ok(Self::Aes256CbcKey(Aes256CbcKey { enc_key }))
            }
            EncodedSymmetricKey::BitwardenLegacyKey(key)
                if key.as_ref().len() == Self::AES256_CBC_HMAC_KEY_LEN =>
            {
                // The legacy byte serialization is defined as `enc_key || mac_key`
                let mut composite_key = Box::pin(Array::<u8, U64>::default());
                composite_key.copy_from_slice(key.as_ref());

                Ok(Self::Aes256CbcHmacKey(Aes256CbcHmacKey {
                    key: composite_key,
                }))
            }
            EncodedSymmetricKey::CoseKey(key) => Self::try_from_cose(key.as_ref()),
            _ => Err(CryptoError::InvalidKey),
        }
    }
}

impl CryptoKey for SymmetricCryptoKey {}

// We manually implement these to make sure we don't print any sensitive data
impl std::fmt::Debug for SymmetricCryptoKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SymmetricCryptoKey::Aes256CbcKey(key) => key.fmt(f),
            SymmetricCryptoKey::Aes256CbcHmacKey(key) => key.fmt(f),
            SymmetricCryptoKey::XChaCha20Poly1305Key(key) => key.fmt(f),
            SymmetricCryptoKey::Aes256GcmKey(key) => key.fmt(f),
            SymmetricCryptoKey::XAes256GcmKey(key) => key.fmt(f),
        }
    }
}

impl std::fmt::Debug for Aes256CbcKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("SymmetricKey::Aes256Cbc");
        #[cfg(feature = "dangerous-crypto-debug")]
        debug_struct.field("key", &hex::encode(self.enc_key.as_slice()));
        debug_struct.finish()
    }
}

impl std::fmt::Debug for Aes256CbcHmacKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("SymmetricKey::Aes256CbcHmac");
        #[cfg(feature = "dangerous-crypto-debug")]
        debug_struct
            .field("enc_key", &hex::encode(self.enc_key()))
            .field("mac_key", &hex::encode(self.mac_key()));
        debug_struct.finish()
    }
}

impl std::fmt::Debug for XChaCha20Poly1305Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("SymmetricKey::XChaCha20Poly1305");
        debug_struct.field("key_id", &self.key_id);
        debug_struct.field(
            "supported_operations",
            &self
                .supported_operations
                .iter()
                .map(|key_operation: &KeyOperation| cose::debug_key_operation(*key_operation))
                .collect::<Vec<_>>(),
        );
        #[cfg(feature = "dangerous-crypto-debug")]
        debug_struct.field("key", &hex::encode(self.enc_key.as_slice()));
        debug_struct.finish()
    }
}

impl std::fmt::Debug for XAes256GcmKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("SymmetricKey::XAes256Gcm");
        debug_struct.field("key_id", &self.key_id);
        debug_struct.field(
            "supported_operations",
            &self
                .supported_operations
                .iter()
                .map(|key_operation: &KeyOperation| cose::debug_key_operation(*key_operation))
                .collect::<Vec<_>>(),
        );
        #[cfg(feature = "dangerous-crypto-debug")]
        debug_struct.field("key", &hex::encode(self.enc_key.as_slice()));
        debug_struct.finish()
    }
}

impl std::fmt::Debug for Aes256GcmKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("SymmetricKey::Aes256Gcm");
        debug_struct.field("key_id", &self.key_id);
        debug_struct.field(
            "supported_operations",
            &self
                .supported_operations
                .iter()
                .map(|key_operation: &KeyOperation| cose::debug_key_operation(*key_operation))
                .collect::<Vec<_>>(),
        );
        #[cfg(feature = "dangerous-crypto-debug")]
        debug_struct.field("key", &hex::encode(self.enc_key.as_slice()));
        debug_struct.finish()
    }
}

/// Pad a key to a minimum length using PKCS7-like padding.
/// The last N bytes of the padded bytes all have the value N.
/// For example, padded to size 4, the value 0,0 becomes 0,0,2,2.
///
/// COSE-serialized keys must be distinguishable from
/// [SymmetricCryptoKey::Aes256CbcHmacKey] keys when encoded as byte arrays with no additional
/// content format. Padding ensures that the byte representation uniquely separates keys by size.
/// The previous key types [SymmetricCryptoKey::Aes256CbcHmacKey] and
/// [SymmetricCryptoKey::Aes256CbcKey] are 64 and 32 bytes long respectively.
fn pad_key(key_bytes: &mut Vec<u8>, min_length: u8) {
    crate::keys::utils::pad_bytes(key_bytes, min_length as usize)
        .expect("Padding cannot fail since the min_length is < 255")
}

/// Unpad a key that is padded using the PKCS7-like padding defined by [pad_key].
/// The last N bytes of the padded bytes all have the value N.
/// For example, padded to size 4, the value 0,0 becomes 0,0,2,2.
///
/// COSE-serialized keys must be distinguishable from
/// [SymmetricCryptoKey::Aes256CbcHmacKey] keys when encoded as byte arrays with no additional
/// content format. Padding ensures that the byte representation uniquely separates keys by size.
/// The previous key types [SymmetricCryptoKey::Aes256CbcHmacKey] and
/// [SymmetricCryptoKey::Aes256CbcKey] are 64 and 32 bytes long respectively.
fn unpad_key(key_bytes: &[u8]) -> Result<&[u8], CryptoError> {
    crate::keys::utils::unpad_bytes(key_bytes).map_err(|_| CryptoError::InvalidKey)
}

/// Encoded representation of [SymmetricCryptoKey]
pub enum EncodedSymmetricKey {
    /// An Aes256-CBC-HMAC key, or a Aes256-CBC key
    BitwardenLegacyKey(BitwardenLegacyKeyBytes),
    /// A symmetric key encoded as a COSE key
    CoseKey(CoseKeyBytes),
}
impl From<EncodedSymmetricKey> for Vec<u8> {
    fn from(val: EncodedSymmetricKey) -> Self {
        match val {
            EncodedSymmetricKey::BitwardenLegacyKey(key) => key.to_vec(),
            EncodedSymmetricKey::CoseKey(key) => key.to_vec(),
        }
    }
}
impl EncodedSymmetricKey {
    /// Returns the content format of the encoded symmetric key.
    #[allow(private_interfaces)]
    pub fn content_format(&self) -> ContentFormat {
        match self {
            EncodedSymmetricKey::BitwardenLegacyKey(_) => ContentFormat::BitwardenLegacyKey,
            EncodedSymmetricKey::CoseKey(_) => ContentFormat::CoseKey,
        }
    }
}

// Note: Deserialize and Serialize are only implemented until external usages of
// symmetric crypto keys are removed. We do not want to support these, but while
// these have to be supported, we want to have type-safety over having raw byte
// arrays.
impl<'de> Deserialize<'de> for SymmetricCryptoKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new())
    }
}

impl FromStr for SymmetricCryptoKey {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = B64::try_from(s.to_string()).map_err(|_| CryptoError::InvalidKey)?;
        Self::try_from(bytes).map_err(|_| CryptoError::InvalidKey)
    }
}

impl Serialize for SymmetricCryptoKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_base64().to_string())
    }
}

/// Test only helper for deriving a symmetric key.
#[cfg(test)]
pub fn derive_symmetric_key(name: &str) -> Aes256CbcHmacKey {
    use zeroize::Zeroizing;

    use crate::{derive_shareable_key, generate_random_bytes};

    let secret: Zeroizing<[u8; 16]> = generate_random_bytes();
    derive_shareable_key(secret, name, None)
}

#[cfg(test)]
mod tests {
    use bitwarden_encoding::B64;
    use coset::{CborSerializable, iana::KeyOperation};
    use hybrid_array::Array;
    use typenum::U32;

    use super::{
        AES256_CBC_HMAC_ENC_KEY_SIZE, EncodedSymmetricKey, KEY_ID_SIZE, SymmetricCryptoKey,
        derive_symmetric_key,
    };
    use crate::{
        Aes256CbcHmacKey, Aes256CbcKey, BitwardenLegacyKeyBytes, CoseKeyThumbprintExt,
        SymmetricKeyAlgorithm, XAes256GcmKey, XChaCha20Poly1305Key,
        keys::{
            KeyId,
            symmetric_crypto_key::{pad_key, unpad_key},
        },
    };

    #[test]
    #[ignore = "Manual test to verify debug format"]
    fn test_key_debug() {
        let aes_key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        println!("{:?}", aes_key);
        let xchacha_key = SymmetricCryptoKey::make_xchacha20_poly1305_key();
        println!("{:?}", xchacha_key);
    }

    #[test]
    fn test_serialize_deserialize_symmetric_crypto_key() {
        let key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        let serialized = serde_json::to_string(&key).unwrap();
        let deserialized: SymmetricCryptoKey = serde_json::from_str(&serialized).unwrap();
        assert_eq!(key, deserialized);
    }

    #[test]
    fn test_symmetric_crypto_key() {
        let key = SymmetricCryptoKey::Aes256CbcHmacKey(derive_symmetric_key("test"));
        let key2 = SymmetricCryptoKey::try_from(key.to_base64()).unwrap();

        assert_eq!(key, key2);

        let key = "UY4B5N4DA4UisCNClgZtRr6VLy9ZF5BXXC7cDZRqourKi4ghEMgISbCsubvgCkHf5DZctQjVot11/vVvN9NNHQ==".to_string();
        let key2 = SymmetricCryptoKey::try_from(key.clone()).unwrap();
        assert_eq!(key, key2.to_base64().to_string());
    }

    #[test]
    fn test_encode_decode_old_symmetric_crypto_key() {
        let key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        let encoded = key.to_encoded();
        let decoded = SymmetricCryptoKey::try_from(&encoded).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn test_decode_new_symmetric_crypto_key() {
        let key: B64 = ("pQEEAlDib+JxbqMBlcd3KTUesbufAzoAARFvBIQDBAUGIFggt79surJXmqhPhYuuqi9ZyPfieebmtw2OsmN5SDrb4yUB").parse()
        .unwrap();
        let key = BitwardenLegacyKeyBytes::from(&key);
        let key = SymmetricCryptoKey::try_from(&key).unwrap();
        match key {
            SymmetricCryptoKey::XChaCha20Poly1305Key(_) => (),
            _ => panic!("Invalid key type"),
        }
    }

    #[test]
    fn test_encode_xchacha20_poly1305_key() {
        let key = SymmetricCryptoKey::make_xchacha20_poly1305_key();
        let encoded = key.to_encoded();
        let decoded = SymmetricCryptoKey::try_from(&encoded).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn test_pad_unpad_key_63() {
        let original_key = vec![1u8; 63];
        let mut key_bytes = original_key.clone();
        let mut encoded_bytes = vec![1u8; 65];
        encoded_bytes[63] = 2;
        encoded_bytes[64] = 2;
        pad_key(&mut key_bytes, 65);
        assert_eq!(encoded_bytes, key_bytes);
        let unpadded_key = unpad_key(&key_bytes).unwrap();
        assert_eq!(original_key, unpadded_key);
    }

    #[test]
    fn test_pad_unpad_key_64() {
        let original_key = vec![1u8; 64];
        let mut key_bytes = original_key.clone();
        let mut encoded_bytes = vec![1u8; 65];
        encoded_bytes[64] = 1;
        pad_key(&mut key_bytes, 65);
        assert_eq!(encoded_bytes, key_bytes);
        let unpadded_key = unpad_key(&key_bytes).unwrap();
        assert_eq!(original_key, unpadded_key);
    }

    #[test]
    fn test_pad_unpad_key_65() {
        let original_key = vec![1u8; 65];
        let mut key_bytes = original_key.clone();
        let mut encoded_bytes = vec![1u8; 66];
        encoded_bytes[65] = 1;
        pad_key(&mut key_bytes, 65);
        assert_eq!(encoded_bytes, key_bytes);
        let unpadded_key = unpad_key(&key_bytes).unwrap();
        assert_eq!(original_key, unpadded_key);
    }

    #[test]
    fn test_eq_aes_cbc_hmac() {
        let key1 = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        let key2 = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        assert_ne!(key1, key2);
        let key3 = SymmetricCryptoKey::try_from(key1.to_base64()).unwrap();
        assert_eq!(key1, key3);
    }

    #[test]
    fn test_eq_aes_cbc() {
        let key1 =
            SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(vec![1u8; 32])).unwrap();
        let key2 =
            SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(vec![2u8; 32])).unwrap();
        assert_ne!(key1, key2);
        let key3 = SymmetricCryptoKey::try_from(key1.to_base64()).unwrap();
        assert_eq!(key1, key3);
    }

    #[test]
    fn test_eq_xchacha20_poly1305() {
        let key1 = SymmetricCryptoKey::make_xchacha20_poly1305_key();
        let key2 = SymmetricCryptoKey::make_xchacha20_poly1305_key();
        assert_ne!(key1, key2);
        let key3 = SymmetricCryptoKey::try_from(key1.to_base64()).unwrap();
        assert_eq!(key1, key3);
    }

    #[test]
    fn test_neq_different_key_types() {
        let key1 = SymmetricCryptoKey::Aes256CbcKey(Aes256CbcKey {
            enc_key: Box::pin(Array::<u8, U32>::default()),
        });
        let key2 = SymmetricCryptoKey::XChaCha20Poly1305Key(XChaCha20Poly1305Key {
            enc_key: Box::pin(Array::<u8, U32>::default()),
            key_id: KeyId::from([0; 16]),
            supported_operations: vec![
                KeyOperation::Decrypt,
                KeyOperation::Encrypt,
                KeyOperation::WrapKey,
                KeyOperation::UnwrapKey,
            ],
        });
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_eq_variant_aes256_cbc() {
        let key1 = Aes256CbcKey {
            enc_key: Box::pin(Array::from([1u8; 32])),
        };
        let key2 = Aes256CbcKey {
            enc_key: Box::pin(Array::from([1u8; 32])),
        };
        let key3 = Aes256CbcKey {
            enc_key: Box::pin(Array::from([2u8; 32])),
        };
        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_eq_variant_aes256_cbc_hmac() {
        let key1 = Aes256CbcHmacKey::new(&[1u8; 32], &[2u8; 32]);
        let key2 = Aes256CbcHmacKey::new(&[1u8; 32], &[2u8; 32]);
        let key3 = Aes256CbcHmacKey::new(&[3u8; 32], &[4u8; 32]);
        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_eq_variant_xchacha20_poly1305() {
        let key1 = XChaCha20Poly1305Key {
            enc_key: Box::pin(Array::from([1u8; 32])),
            key_id: KeyId::from([0; 16]),
            supported_operations: vec![
                KeyOperation::Decrypt,
                KeyOperation::Encrypt,
                KeyOperation::WrapKey,
                KeyOperation::UnwrapKey,
            ],
        };
        let key2 = XChaCha20Poly1305Key {
            enc_key: Box::pin(Array::from([1u8; 32])),
            key_id: KeyId::from([0; 16]),
            supported_operations: vec![
                KeyOperation::Decrypt,
                KeyOperation::Encrypt,
                KeyOperation::WrapKey,
                KeyOperation::UnwrapKey,
            ],
        };
        let key3 = XChaCha20Poly1305Key {
            enc_key: Box::pin(Array::from([2u8; 32])),
            key_id: KeyId::from([1; 16]),
            supported_operations: vec![
                KeyOperation::Decrypt,
                KeyOperation::Encrypt,
                KeyOperation::WrapKey,
                KeyOperation::UnwrapKey,
            ],
        };
        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    fn fixed_xaes_key_inner() -> XAes256GcmKey {
        XAes256GcmKey {
            enc_key: Box::pin(Array::from([
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ])),
            key_id: KeyId::from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
            supported_operations: vec![KeyOperation::Encrypt, KeyOperation::Decrypt],
        }
    }

    fn fixed_xaes_key() -> SymmetricCryptoKey {
        SymmetricCryptoKey::XAes256GcmKey(fixed_xaes_key_inner())
    }

    #[test]
    fn test_make_xaes256_gcm_key() {
        assert!(matches!(
            SymmetricCryptoKey::make(SymmetricKeyAlgorithm::XAes256Gcm),
            SymmetricCryptoKey::XAes256GcmKey(_)
        ));
    }

    #[test]
    fn test_xaes256_gcm_encoding_roundtrips() {
        const PADDED_KEY: &str = "pQEEAlAAAQIDBAUGBwgJCgsMDQ4PAzoAARF5BIIDBCBYIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fAQ==";

        let key = fixed_xaes_key();
        assert_eq!(key.to_base64().to_string(), PADDED_KEY);
        let padded = SymmetricCryptoKey::try_from(PADDED_KEY.to_owned()).unwrap();
        assert_eq!(padded, key);
        let SymmetricCryptoKey::XAes256GcmKey(ref padded) = padded else {
            panic!("expected XAES-256-GCM key");
        };
        assert_eq!(
            padded.supported_operations,
            [KeyOperation::Encrypt, KeyOperation::Decrypt]
        );

        let EncodedSymmetricKey::CoseKey(raw) = key.to_encoded_raw() else {
            panic!("expected COSE key encoding");
        };
        assert_eq!(
            SymmetricCryptoKey::try_from_cose(raw.as_ref()).unwrap(),
            key
        );

        let cose_key = coset::CoseKey::from_slice(raw.as_ref()).unwrap();
        assert_eq!(
            cose_key.alg,
            Some(coset::Algorithm::PrivateUse(crate::cose::XAES_256_GCM))
        );
        assert_eq!(cose_key.key_id, (0u8..16).collect::<Vec<_>>());
        assert_eq!(cose_key.key_ops.len(), 2);
        assert!(
            cose_key
                .key_ops
                .contains(&coset::RegisteredLabel::Assigned(KeyOperation::Encrypt))
        );
        assert!(
            cose_key
                .key_ops
                .contains(&coset::RegisteredLabel::Assigned(KeyOperation::Decrypt))
        );
    }

    #[test]
    fn test_xaes256_gcm_equality() {
        let key = fixed_xaes_key();
        let same = fixed_xaes_key();
        assert_eq!(key, same);

        let mut different_bytes = fixed_xaes_key_inner();
        different_bytes.enc_key[0] ^= 1;
        assert_ne!(key, SymmetricCryptoKey::XAes256GcmKey(different_bytes));

        let mut different_id = fixed_xaes_key_inner();
        different_id.key_id = KeyId::from([1; 16]);
        assert_ne!(key, SymmetricCryptoKey::XAes256GcmKey(different_id));

        for other in [
            SymmetricCryptoKey::Aes256CbcKey(Aes256CbcKey {
                enc_key: Box::pin(Array::default()),
            }),
            SymmetricCryptoKey::Aes256CbcHmacKey(Aes256CbcHmacKey::new(&[0u8; 32], &[0u8; 32])),
            SymmetricCryptoKey::Aes256GcmKey(crate::Aes256GcmKey::make()),
            SymmetricCryptoKey::XChaCha20Poly1305Key(XChaCha20Poly1305Key::make()),
        ] {
            assert_ne!(key, other);
        }
    }

    #[test]
    fn test_neq_different_key_id() {
        let key1 = XChaCha20Poly1305Key {
            enc_key: Box::pin(Array::<u8, U32>::default()),
            key_id: KeyId::from([0; 16]),
            supported_operations: vec![
                KeyOperation::Decrypt,
                KeyOperation::Encrypt,
                KeyOperation::WrapKey,
                KeyOperation::UnwrapKey,
            ],
        };
        let key2 = XChaCha20Poly1305Key {
            enc_key: Box::pin(Array::<u8, U32>::default()),
            key_id: KeyId::from([1; 16]),
            supported_operations: vec![
                KeyOperation::Decrypt,
                KeyOperation::Encrypt,
                KeyOperation::WrapKey,
                KeyOperation::UnwrapKey,
            ],
        };
        assert_ne!(key1, key2);

        let key1 = SymmetricCryptoKey::XChaCha20Poly1305Key(key1);
        let key2 = SymmetricCryptoKey::XChaCha20Poly1305Key(key2);
        assert_ne!(key1, key2);
    }

    const AES256_GCM_KEY: &str =
        "pQEEAlACAgICAgICAgICAgICAgICAwMEhAMEBQYgWCABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const AES256_GCM_KEY_THUMBPRINT: &str =
        "3810c7275ee292caca13d938a057a94c75210087d960d3eb6868c0ffe99b5643";

    const XCHACHA20_POLY1305_KEY: &str = "pQEEAlDib+JxbqMBlcd3KTUesbufAzoAARFvBIQDBAUGIFggt79surJXmqhPhYuuqi9ZyPfieebmtw2OsmN5SDrb4yUB";
    const XCHACHA20_POLY1305_KEY_THUMBPRINT: &str =
        "64aec2d09ef5ba8b310ef9a70346b03422443e295b6f045e38169ae97e579d85";

    #[test]
    fn test_decode_new_aes256_gcm_key() {
        let key: B64 = AES256_GCM_KEY.parse().unwrap();
        let key = SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(&key)).unwrap();
        match key {
            SymmetricCryptoKey::Aes256GcmKey(_) => (),
            _ => panic!("Invalid key type"),
        }
    }

    #[test]
    fn test_thumbprint_aes256_gcm_vector() {
        // A fixed AES-256-GCM COSE key.
        let key: B64 = AES256_GCM_KEY.parse().unwrap();
        let key = SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(&key)).unwrap();
        assert_eq!(
            key.thumbprint().unwrap().to_hex(),
            AES256_GCM_KEY_THUMBPRINT
        );
    }

    #[test]
    fn test_thumbprint_xchacha20_poly1305_vector() {
        // A fixed XChaCha20Poly1305 COSE key.
        let key: B64 = XCHACHA20_POLY1305_KEY.parse().unwrap();
        let key = SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(&key)).unwrap();
        assert_eq!(
            key.thumbprint().unwrap().to_hex(),
            XCHACHA20_POLY1305_KEY_THUMBPRINT
        );
    }

    #[test]
    fn test_thumbprint_is_deterministic() {
        let key = SymmetricCryptoKey::make_xchacha20_poly1305_key();
        assert_eq!(key.thumbprint().unwrap(), key.thumbprint().unwrap());
    }

    /// The unauthenticated AES-CBC key is the only variant with no COSE key view, and so the only
    /// one without a thumbprint.
    #[test]
    fn test_thumbprint_errors_for_unauthenticated_aes_cbc() {
        let key = SymmetricCryptoKey::Aes256CbcKey(Aes256CbcKey {
            enc_key: Box::pin(Array::from([1u8; 32])),
        });
        assert!(key.thumbprint().is_err());
    }

    const AES256_CBC_HMAC_KEY_THUMBPRINT: &str =
        "ac4ecffb2e087a59180d1dd19950b8e9e634997f47bbfd7a2bb829edf7a9f900";
    const AES256_CBC_HMAC_KEY_ID: &str = "ac4ecffb2e087a59180d1dd19950b8e9";

    /// A fixed AES-256-CBC-HMAC key: `enc_key` is `0x00..0x1f`, `mac_key` is `0x20..0x3f`.
    fn fixed_aes_cbc_hmac_key_inner() -> Aes256CbcHmacKey {
        Aes256CbcHmacKey::new(
            &std::array::from_fn(|i| i as u8),
            &std::array::from_fn(|i| (i + 32) as u8),
        )
    }

    fn fixed_aes_cbc_hmac_key() -> SymmetricCryptoKey {
        SymmetricCryptoKey::Aes256CbcHmacKey(fixed_aes_cbc_hmac_key_inner())
    }

    #[test]
    #[ignore = "Generates test vectors; run manually"]
    fn generate_aes256_cbc_hmac_thumbprint_vectors() {
        let key = fixed_aes_cbc_hmac_key();
        println!(
            "const AES256_CBC_HMAC_KEY_THUMBPRINT: &str = \"{}\";",
            key.thumbprint().unwrap().to_hex()
        );
        println!(
            "const AES256_CBC_HMAC_KEY_ID: &str = \"{}\";",
            hex::encode(key.key_id().unwrap().as_slice())
        );
    }

    /// Locks in the thumbprint of an AES-256-CBC-HMAC key: the RFC 9679 thumbprint of a COSE
    /// `Symmetric` key whose `k` is the 64-byte `enc_key || mac_key` composite. The derived key ID
    /// depends on this, so it must never change.
    #[test]
    fn test_thumbprint_aes256_cbc_hmac_vector() {
        assert_eq!(
            fixed_aes_cbc_hmac_key().thumbprint().unwrap().to_hex(),
            AES256_CBC_HMAC_KEY_THUMBPRINT
        );
    }

    #[test]
    fn test_key_id_aes256_cbc_hmac_vector() {
        let key_id = fixed_aes_cbc_hmac_key().key_id().unwrap();
        assert_eq!(hex::encode(key_id.as_slice()), AES256_CBC_HMAC_KEY_ID);
    }

    /// Locks in the derivation rule itself: the key ID is the leading `KEY_ID_SIZE` bytes of the
    /// key's thumbprint.
    #[test]
    fn test_key_id_is_thumbprint_prefix() {
        let key = fixed_aes_cbc_hmac_key();
        let thumbprint = key.thumbprint().unwrap();
        assert_eq!(
            key.key_id().unwrap().as_slice(),
            &thumbprint.as_bytes()[..KEY_ID_SIZE]
        );
    }

    #[test]
    fn test_key_id_aes256_cbc_hmac_is_deterministic() {
        assert_eq!(
            fixed_aes_cbc_hmac_key().key_id(),
            fixed_aes_cbc_hmac_key().key_id()
        );
    }

    /// Both halves of the key must feed the ID, or two keys differing only in their MAC key would
    /// collide.
    #[test]
    fn test_key_id_aes256_cbc_hmac_covers_both_halves() {
        let key = fixed_aes_cbc_hmac_key();

        // Flip the first byte of the encryption half, then of the MAC half.
        let mut different_enc = fixed_aes_cbc_hmac_key_inner();
        different_enc.key[0] ^= 1;
        assert_ne!(
            key.key_id(),
            SymmetricCryptoKey::Aes256CbcHmacKey(different_enc).key_id()
        );

        let mut different_mac = fixed_aes_cbc_hmac_key_inner();
        different_mac.key[AES256_CBC_HMAC_ENC_KEY_SIZE] ^= 1;
        assert_ne!(
            key.key_id(),
            SymmetricCryptoKey::Aes256CbcHmacKey(different_mac).key_id()
        );
    }

    /// Having a COSE key view must not change how these keys are serialized: they remain the raw
    /// 64-byte legacy encoding. Changing this would break every existing user key.
    #[test]
    fn test_aes256_cbc_hmac_still_encodes_as_legacy_64_bytes() {
        let key = fixed_aes_cbc_hmac_key();

        let EncodedSymmetricKey::BitwardenLegacyKey(raw) = key.to_encoded_raw() else {
            panic!("expected legacy key encoding");
        };
        assert_eq!(raw.as_ref().len(), 64);
        assert_eq!(raw.as_ref(), (0u8..64).collect::<Vec<_>>());

        assert_eq!(key.to_encoded().as_ref().len(), 64);
        assert_eq!(SymmetricCryptoKey::try_from(key.to_base64()).unwrap(), key);
    }
}

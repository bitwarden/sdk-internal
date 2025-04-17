use std::{cmp::max, pin::Pin};

use aes::cipher::typenum::U32;
use base64::{engine::general_purpose::STANDARD, Engine};
use coset::{iana, CborSerializable, Label, RegisteredLabelWithPrivate};
use generic_array::GenericArray;
use rand::Rng;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{key_encryptable::CryptoKey, key_id::KeyId};
use crate::{cose, CryptoError};

/// Aes256CbcKey is a symmetric encryption key, consisting of one 256-bit key,
/// used to decrypt legacy type 0 encstrings. The data is not autenticated
/// so this should be used with caution, and removed where possible.
#[derive(ZeroizeOnDrop, Clone)]
pub struct Aes256CbcKey {
    /// Uses a pinned heap data structure, as noted in [Pinned heap data][crate#pinned-heap-data]
    pub(crate) enc_key: Pin<Box<GenericArray<u8, U32>>>,
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

/// Aes256CbcHmacKey is a symmetric encryption key consisting
/// of two 256-bit keys, one for encryption and one for MAC
#[derive(ZeroizeOnDrop, Clone)]
pub struct Aes256CbcHmacKey {
    /// Uses a pinned heap data structure, as noted in [Pinned heap data][crate#pinned-heap-data]
    pub(crate) enc_key: Pin<Box<GenericArray<u8, U32>>>,
    /// Uses a pinned heap data structure, as noted in [Pinned heap data][crate#pinned-heap-data]
    pub(crate) mac_key: Pin<Box<GenericArray<u8, U32>>>,
}

impl ConstantTimeEq for Aes256CbcHmacKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.enc_key.ct_eq(&other.enc_key) & self.mac_key.ct_eq(&other.mac_key)
    }
}

impl PartialEq for Aes256CbcHmacKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

#[derive(Zeroize, Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct XChaCha20Poly1305Key {
    pub(crate) key_id: [u8; 24],
    pub(crate) enc_key: Pin<Box<GenericArray<u8, U32>>>,
}

impl ConstantTimeEq for XChaCha20Poly1305Key {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.enc_key.ct_eq(&other.enc_key)
    }
}

impl PartialEq for XChaCha20Poly1305Key {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

/// A symmetric encryption key. Used to encrypt and decrypt [`EncString`](crate::EncString)
#[derive(ZeroizeOnDrop, Clone)]
pub enum SymmetricCryptoKey {
    Aes256CbcKey(Aes256CbcKey),
    Aes256CbcHmacKey(Aes256CbcHmacKey),
    // always encode with cose
    XChaCha20Poly1305Key(XChaCha20Poly1305Key),
}

impl SymmetricCryptoKey {
    // enc type 0 old static format
    const AES256_CBC_KEY_LEN: usize = 32;
    // enc type 2 old static format
    const AES256_CBC_HMAC_KEY_LEN: usize = 64;

    /**
     * Generate a new random AES256_CBC_HMAC [SymmetricCryptoKey]
     */
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        Self::generate_internal(&mut rng, false)
    }

    /**
     * Generate a new random XChaCha20Poly1305 [SymmetricCryptoKey]
     */
    pub fn generate_xchacha20() -> Self {
        let mut rng = rand::thread_rng();
        Self::generate_internal(&mut rng, true)
    }

    /// Generate a new random [SymmetricCryptoKey]
    /// @param rng: A random number generator
    /// @param xchacha: If true, generate an XChaCha20Poly1305 key, otherwise generate an
    /// AES256_CBC_HMAC key
    pub(crate) fn generate_internal(mut rng: impl rand::RngCore, xchacha20: bool) -> Self {
        if !xchacha20 {
            let mut enc_key = Box::pin(GenericArray::<u8, U32>::default());
            let mut mac_key = Box::pin(GenericArray::<u8, U32>::default());

            rng.fill(enc_key.as_mut_slice());
            rng.fill(mac_key.as_mut_slice());

            SymmetricCryptoKey::Aes256CbcHmacKey(Aes256CbcHmacKey { enc_key, mac_key })
        } else {
            let mut enc_key = Box::pin(GenericArray::<u8, U32>::default());
            rng.fill(enc_key.as_mut_slice());
            SymmetricCryptoKey::XChaCha20Poly1305Key(XChaCha20Poly1305Key {
                enc_key,
                key_id: *KeyId::generate().as_bytes(),
            })
        }
    }

    /// Encodes the key to a byte array representation, that is separated by size.
    /// `SymmetricCryptoKey::Aes256CbcHmacKey` and `SymmetricCryptoKey::Aes256CbcKey` are
    /// encoded as 64 and 32 bytes respectively. `SymmetricCryptoKey::XChaCha20Poly1305Key`
    /// is encoded as at least 65 bytes, by using padding defined in `pad_key`.
    ///
    /// This can be used for storage and transmission in the old byte array format.
    /// When the wrapping key is a COSE key, and the wrapped key is a COSE key, then this should
    /// not use the byte representation but instead use the COSE key representation.
    pub fn to_encoded(&self) -> Vec<u8> {
        let mut encoded_key = self.to_encoded_raw();
        match self {
            SymmetricCryptoKey::Aes256CbcKey(_) | SymmetricCryptoKey::Aes256CbcHmacKey(_) => {
                encoded_key
            }
            SymmetricCryptoKey::XChaCha20Poly1305Key(_) => {
                pad_key(&mut encoded_key, Self::AES256_CBC_HMAC_KEY_LEN + 1);
                encoded_key
            }
        }
    }

    pub(crate) fn to_encoded_raw(&self) -> Vec<u8> {
        match self {
            SymmetricCryptoKey::Aes256CbcKey(key) => key.enc_key.to_vec(),
            SymmetricCryptoKey::Aes256CbcHmacKey(key) => {
                let mut buf = Vec::with_capacity(64);
                buf.extend_from_slice(&key.enc_key);
                buf.extend_from_slice(&key.mac_key);
                buf
            }
            SymmetricCryptoKey::XChaCha20Poly1305Key(key) => {
                let builder = coset::CoseKeyBuilder::new_symmetric_key(key.enc_key.to_vec());
                let mut cose_key = builder
                    .key_id(key.key_id.to_vec())
                    .add_key_op(iana::KeyOperation::Decrypt)
                    .add_key_op(iana::KeyOperation::Encrypt)
                    .add_key_op(iana::KeyOperation::WrapKey)
                    .add_key_op(iana::KeyOperation::UnwrapKey)
                    .build();
                cose_key.alg = Some(RegisteredLabelWithPrivate::PrivateUse(
                    cose::XCHACHA20_POLY1305,
                ));
                cose_key
                    .to_vec()
                    .map_err(|_| CryptoError::InvalidKey)
                    .expect("Failed to encode key")
            }
        }
    }

    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.to_encoded())
    }
}

impl ConstantTimeEq for SymmetricCryptoKey {
    fn ct_eq(&self, other: &SymmetricCryptoKey) -> Choice {
        use SymmetricCryptoKey::*;
        match (self, other) {
            (Aes256CbcKey(a), Aes256CbcKey(b)) => a.ct_eq(b),
            (Aes256CbcKey(_), _) => Choice::from(0),

            (Aes256CbcHmacKey(a), Aes256CbcHmacKey(b)) => a.ct_eq(b),
            (Aes256CbcHmacKey(_), _) => Choice::from(0),

            (XChaCha20Poly1305Key(a), XChaCha20Poly1305Key(b)) => a.ct_eq(b),
            (XChaCha20Poly1305Key(_), _) => Choice::from(0),
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
        let b = STANDARD
            .decode(value)
            .map_err(|_| CryptoError::InvalidKey)?;
        SymmetricCryptoKey::try_from(b)
    }
}

impl TryFrom<Vec<u8>> for SymmetricCryptoKey {
    type Error = CryptoError;

    fn try_from(mut value: Vec<u8>) -> Result<Self, Self::Error> {
        SymmetricCryptoKey::try_from(value.as_mut_slice())
    }
}

impl TryFrom<&mut [u8]> for SymmetricCryptoKey {
    type Error = CryptoError;

    /// Note: This function takes the byte slice by mutable reference and will zero out all
    /// the data in it. This is to prevent the key from being left in memory.
    fn try_from(value: &mut [u8]) -> Result<Self, Self::Error> {
        // Raw byte serialized keys are either 32, 64, or more bytes long. If they are 32/64, they
        // are the raw serializations of the AES256-CBC, and AES256-CBC-HMAC keys. If they
        // are longer, they are COSE keys. The COSE keys are padded to the minimum length of
        // 65 bytes, when serialized to raw byte arrays.
        let result = if value.len() == Self::AES256_CBC_HMAC_KEY_LEN {
            let mut enc_key = Box::pin(GenericArray::<u8, U32>::default());
            let mut mac_key = Box::pin(GenericArray::<u8, U32>::default());

            enc_key.copy_from_slice(&value[..32]);
            mac_key.copy_from_slice(&value[32..]);

            Ok(SymmetricCryptoKey::Aes256CbcHmacKey(Aes256CbcHmacKey {
                enc_key,
                mac_key,
            }))
        } else if value.len() == Self::AES256_CBC_KEY_LEN {
            let mut enc_key = Box::pin(GenericArray::<u8, U32>::default());

            enc_key.copy_from_slice(&value[..Self::AES256_CBC_KEY_LEN]);

            Ok(SymmetricCryptoKey::Aes256CbcKey(Aes256CbcKey { enc_key }))
        } else if value.len() > Self::AES256_CBC_HMAC_KEY_LEN {
            let unpadded_value = unpad_key(value);
            let cose_key =
                coset::CoseKey::from_slice(unpadded_value).map_err(|_| CryptoError::InvalidKey)?;
            parse_cose_key(&cose_key)
        } else {
            Err(CryptoError::InvalidKeyLen)
        };

        value.zeroize();
        result
    }
}

fn parse_cose_key(cose_key: &coset::CoseKey) -> Result<SymmetricCryptoKey, CryptoError> {
    let key_bytes = cose_key
        .params
        .iter()
        .find_map(|(label, value)| {
            const SYMMETRIC_KEY: i64 = iana::SymmetricKeyParameter::K as i64;
            if let (Label::Int(SYMMETRIC_KEY), ciborium::Value::Bytes(bytes)) = (label, value) {
                Some(bytes)
            } else {
                None
            }
        })
        .ok_or(CryptoError::InvalidKey)?;

    match cose_key.alg.clone().ok_or(CryptoError::InvalidKey)? {
        coset::RegisteredLabelWithPrivate::PrivateUse(cose::XCHACHA20_POLY1305) => {
            if key_bytes.len() == 32 {
                let mut enc_key = Box::pin(GenericArray::<u8, U32>::default());
                enc_key.copy_from_slice(key_bytes);
                let key_id = cose_key
                    .key_id
                    .clone()
                    .try_into()
                    .map_err(|_| CryptoError::InvalidKey)?;
                Ok(SymmetricCryptoKey::XChaCha20Poly1305Key(
                    XChaCha20Poly1305Key { enc_key, key_id },
                ))
            } else {
                Err(CryptoError::InvalidKey)
            }
        }
        _ => Err(CryptoError::InvalidKey),
    }
}

impl CryptoKey for SymmetricCryptoKey {}

// We manually implement these to make sure we don't print any sensitive data
impl std::fmt::Debug for SymmetricCryptoKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymmetricCryptoKey").finish()
    }
}

/// Pad a key to a minimum length using PKCS7-like padding.
/// The last N bytes of the padded bytes all have the value N.
/// For example, padded to size 4, the value 0,0 becomes 0,0,2,2.
///
/// Keys that have the type `SymmetricCryptoKey::XChaCha20Poly1305Key` must be distinguishable
/// from `SymmetricCryptoKey::Aes256CbcHmacKey` keys, when both are encoded as byte arrays
/// with no additional content format included in the encoding message. For this reason, the
/// padding is used to make sure that the byte representation uniquely separates the keys by
/// size of the byte array. The previous key types `SymmetricCryptoKey::Aes256CbcHmacKey` and
/// `SymmetricCryptoKey::Aes256CbcKey` are 64 and 32 bytes long respectively.
fn pad_key(key_bytes: &mut Vec<u8>, min_length: usize) {
    // at least 1 byte of padding is required
    let pad_bytes = min_length.saturating_sub(key_bytes.len()).max(1);
    let padded_length = max(min_length, key_bytes.len() + 1);
    key_bytes.resize(padded_length, pad_bytes as u8);
}

/// Unpad a key that is padded using the PKCS7-like padding defined by `pad_key`.
/// The last N bytes of the padded bytes all have the value N.
/// For example, padded to size 4, the value 0,0 becomes 0,0,2,2.
///
/// Keys that have the type `SymmetricCryptoKey::XChaCha20Poly1305Key` must be distinguishable
/// from `SymmetricCryptoKey::Aes256CbcHmacKey` keys, when both are encoded as byte arrays
/// with no additional content format included in the encoding message. For this reason, the
/// padding is used to make sure that the byte representation uniquely separates the keys by
/// size of the byte array the previous key types `SymmetricCryptoKey::Aes256CbcHmacKey` and
/// `SymmetricCryptoKey::Aes256CbcKey` are 64 and 32 bytes long respectively.
fn unpad_key(key_bytes: &[u8]) -> &[u8] {
    // this unwrap is safe, the input is always at least 1 byte long
    #[allow(clippy::unwrap_used)]
    let pad_len = *key_bytes.last().unwrap() as usize;
    key_bytes[..key_bytes.len() - pad_len].as_ref()
}

#[cfg(test)]
pub fn derive_symmetric_key(name: &str) -> Aes256CbcHmacKey {
    use zeroize::Zeroizing;

    use crate::{derive_shareable_key, generate_random_bytes};

    let secret: Zeroizing<[u8; 16]> = generate_random_bytes();
    derive_shareable_key(secret, name, None)
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine};

    use super::{derive_symmetric_key, SymmetricCryptoKey};
    use crate::keys::symmetric_crypto_key::{pad_key, unpad_key};

    #[test]
    fn test_symmetric_crypto_key() {
        let key = SymmetricCryptoKey::Aes256CbcHmacKey(derive_symmetric_key("test"));
        let key2 = SymmetricCryptoKey::try_from(key.to_base64()).unwrap();

        assert_eq!(key, key2);

        let key = "UY4B5N4DA4UisCNClgZtRr6VLy9ZF5BXXC7cDZRqourKi4ghEMgISbCsubvgCkHf5DZctQjVot11/vVvN9NNHQ==".to_string();
        let key2 = SymmetricCryptoKey::try_from(key.clone()).unwrap();
        assert_eq!(key, key2.to_base64());
    }

    #[test]
    fn test_encode_decode_old_symmetric_crypto_key() {
        let key = SymmetricCryptoKey::generate_internal(rand::thread_rng(), false);
        let encoded = key.to_encoded();
        let decoded = SymmetricCryptoKey::try_from(encoded).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn test_decode_new_symmetric_crypto_key() {
        let key_b64 = STANDARD.decode("pQEEAlgYsfduEfedSKOr789AUhNKgVKXMAS2xUHlAzoAARFvBIQDBAUGIFggewlpLfp0GhDar/kSozu3KLaWShfwuiMAPrO+vrIG2m4B").unwrap();
        let key = SymmetricCryptoKey::try_from(key_b64).unwrap();
        match key {
            SymmetricCryptoKey::XChaCha20Poly1305Key(_) => (),
            _ => panic!("Invalid key type"),
        }
    }

    #[test]
    fn test_encode_xchacha20_poly1305_key() {
        let key = SymmetricCryptoKey::generate_internal(rand::thread_rng(), true);
        let key_vec = key.to_encoded();
        let key_vec_utf8_lossy = String::from_utf8_lossy(&key_vec);
        println!("key_vec: {:?}", key_vec_utf8_lossy);
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
        let unpadded_key = unpad_key(&key_bytes);
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
        let unpadded_key = unpad_key(&key_bytes);
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
        let unpadded_key = unpad_key(&key_bytes);
        assert_eq!(original_key, unpadded_key);
    }
}

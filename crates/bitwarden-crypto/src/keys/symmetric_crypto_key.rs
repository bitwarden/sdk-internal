use std::{cmp::max, pin::Pin};

use aes::cipher::typenum::U32;
use base64::{engine::general_purpose::STANDARD, Engine};
use coset::{iana::KeyOperation, CborSerializable, RegisteredLabelWithPrivate};
use generic_array::GenericArray;
use rand::Rng;
#[cfg(test)]
use rand::SeedableRng;
#[cfg(test)]
use rand_chacha::ChaChaRng;
#[cfg(test)]
use sha2::Digest;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{key_encryptable::CryptoKey, key_id::KeyId};
use crate::{cose, CryptoError};

/// [Aes256CbcKey] is a symmetric encryption key, consisting of one 256-bit key,
/// used to decrypt legacy type 0 enc strings. The data is not authenticated
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

/// [Aes256CbcHmacKey] is a symmetric encryption key consisting
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
    /// Data encrypted by XChaCha20Poly1305Key keys has type
    /// [`Cose_Encrypt0_B64`](crate::EncString::Cose_Encrypt0_B64)
    XChaCha20Poly1305Key(XChaCha20Poly1305Key),
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
    pub(crate) fn make_aes256_cbc_hmac_key_internal(
        mut rng: impl rand::RngCore + rand::CryptoRng,
    ) -> Self {
        let mut enc_key = Box::pin(GenericArray::<u8, U32>::default());
        let mut mac_key = Box::pin(GenericArray::<u8, U32>::default());

        rng.fill(enc_key.as_mut_slice());
        rng.fill(mac_key.as_mut_slice());

        Self::Aes256CbcHmacKey(Aes256CbcHmacKey { enc_key, mac_key })
    }

    /// Generate a new random AES256_CBC_HMAC [SymmetricCryptoKey]
    pub fn make_aes256_cbc_hmac_key() -> Self {
        let mut rng = rand::thread_rng();
        Self::make_aes256_cbc_hmac_key_internal(&mut rng)
    }

    /// Generate a new random XChaCha20Poly1305 [SymmetricCryptoKey]
    pub fn make_xchacha20_poly1305_key() -> Self {
        let mut rng = rand::thread_rng();
        let mut enc_key = Box::pin(GenericArray::<u8, U32>::default());
        rng.fill(enc_key.as_mut_slice());
        Self::XChaCha20Poly1305Key(XChaCha20Poly1305Key {
            enc_key,
            key_id: *KeyId::generate().as_bytes(),
        })
    }

    /// Encodes the key to a byte array representation, that is separated by size.
    /// [SymmetricCryptoKey::Aes256CbcHmacKey] and [SymmetricCryptoKey::Aes256CbcKey] are
    /// encoded as 64 and 32 bytes respectively. [SymmetricCryptoKey::XChaCha20Poly1305Key]
    /// is encoded as at least 65 bytes, using padding.
    ///
    /// This can be used for storage and transmission in the old byte array format.
    /// When the wrapping key is a COSE key, and the wrapped key is a COSE key, then this should
    /// not use the byte representation but instead use the COSE key representation.
    pub fn to_encoded(&self) -> Vec<u8> {
        let mut encoded_key = self.to_encoded_raw();
        match self {
            Self::Aes256CbcKey(_) | Self::Aes256CbcHmacKey(_) => encoded_key,
            Self::XChaCha20Poly1305Key(_) => {
                pad_key(&mut encoded_key, Self::AES256_CBC_HMAC_KEY_LEN + 1);
                encoded_key
            }
        }
    }

    /// Generate a new random [SymmetricCryptoKey] for unit tests. Note: DO NOT USE THIS
    /// IN PRODUCTION CODE.
    #[cfg(test)]
    pub fn generate_seeded_for_unit_tests(seed: &str) -> Self {
        // Keep this separate from the other generate function to not break test vectors.
        let mut seeded_rng = ChaChaRng::from_seed(sha2::Sha256::digest(seed.as_bytes()).into());
        let mut enc_key = Box::pin(GenericArray::<u8, U32>::default());
        let mut mac_key = Box::pin(GenericArray::<u8, U32>::default());

        seeded_rng.fill(enc_key.as_mut_slice());
        seeded_rng.fill(mac_key.as_mut_slice());

        SymmetricCryptoKey::Aes256CbcHmacKey(Aes256CbcHmacKey { enc_key, mac_key })
    }

    pub(crate) fn to_encoded_raw(&self) -> Vec<u8> {
        match self {
            Self::Aes256CbcKey(key) => key.enc_key.to_vec(),
            Self::Aes256CbcHmacKey(key) => {
                let mut buf = Vec::with_capacity(64);
                buf.extend_from_slice(&key.enc_key);
                buf.extend_from_slice(&key.mac_key);
                buf
            }
            Self::XChaCha20Poly1305Key(key) => {
                let builder = coset::CoseKeyBuilder::new_symmetric_key(key.enc_key.to_vec());
                let mut cose_key = builder
                    .key_id(key.key_id.to_vec())
                    .add_key_op(KeyOperation::Decrypt)
                    .add_key_op(KeyOperation::Encrypt)
                    .add_key_op(KeyOperation::WrapKey)
                    .add_key_op(KeyOperation::UnwrapKey)
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
        Self::try_from(b)
    }
}

impl TryFrom<Vec<u8>> for SymmetricCryptoKey {
    type Error = CryptoError;

    fn try_from(mut value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_mut_slice())
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

            Ok(Self::Aes256CbcHmacKey(Aes256CbcHmacKey {
                enc_key,
                mac_key,
            }))
        } else if value.len() == Self::AES256_CBC_KEY_LEN {
            let mut enc_key = Box::pin(GenericArray::<u8, U32>::default());

            enc_key.copy_from_slice(&value[..Self::AES256_CBC_KEY_LEN]);

            Ok(Self::Aes256CbcKey(Aes256CbcKey { enc_key }))
        } else if value.len() > Self::AES256_CBC_HMAC_KEY_LEN {
            let unpadded_value = unpad_key(value)?;
            let cose_key =
                coset::CoseKey::from_slice(unpadded_value).map_err(|_| CryptoError::InvalidKey)?;
            SymmetricCryptoKey::try_from(&cose_key)
        } else {
            Err(CryptoError::InvalidKeyLen)
        };

        value.zeroize();
        result
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
/// Keys that have the type [SymmetricCryptoKey::XChaCha20Poly1305Key] must be distinguishable
/// from [SymmetricCryptoKey::Aes256CbcHmacKey] keys, when both are encoded as byte arrays
/// with no additional content format included in the encoding message. For this reason, the
/// padding is used to make sure that the byte representation uniquely separates the keys by
/// size of the byte array. The previous key types [SymmetricCryptoKey::Aes256CbcHmacKey] and
/// [SymmetricCryptoKey::Aes256CbcKey] are 64 and 32 bytes long respectively.
fn pad_key(key_bytes: &mut Vec<u8>, min_length: usize) {
    // at least 1 byte of padding is required
    let pad_bytes = min_length.saturating_sub(key_bytes.len()).max(1);
    let padded_length = max(min_length, key_bytes.len() + 1);
    key_bytes.resize(padded_length, pad_bytes as u8);
}

/// Unpad a key that is padded using the PKCS7-like padding defined by [pad_key].
/// The last N bytes of the padded bytes all have the value N.
/// For example, padded to size 4, the value 0,0 becomes 0,0,2,2.
///
/// Keys that have the type [SymmetricCryptoKey::XChaCha20Poly1305Key] must be distinguishable
/// from [SymmetricCryptoKey::Aes256CbcHmacKey] keys, when both are encoded as byte arrays
/// with no additional content format included in the encoding message. For this reason, the
/// padding is used to make sure that the byte representation uniquely separates the keys by
/// size of the byte array the previous key types [SymmetricCryptoKey::Aes256CbcHmacKey] and
/// [SymmetricCryptoKey::Aes256CbcKey] are 64 and 32 bytes long respectively.
fn unpad_key(key_bytes: &[u8]) -> Result<&[u8], CryptoError> {
    let pad_len = *key_bytes.last().ok_or(CryptoError::InvalidKey)? as usize;
    if pad_len >= key_bytes.len() {
        return Err(CryptoError::InvalidKey);
    }
    Ok(key_bytes[..key_bytes.len() - pad_len].as_ref())
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
        let key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
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
        let key = SymmetricCryptoKey::make_xchacha20_poly1305_key();
        let encoded = key.to_encoded();
        let decoded = SymmetricCryptoKey::try_from(encoded).unwrap();
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
}

use std::{cmp::max, pin::Pin};

use aes::cipher::typenum::U32;
use base64::{engine::general_purpose::STANDARD, Engine};
use generic_array::GenericArray;
use rand::Rng;
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::key_encryptable::CryptoKey;
use crate::CryptoError;

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

/// A symmetric encryption key. Used to encrypt and decrypt [`EncString`](crate::EncString)
#[derive(ZeroizeOnDrop, Clone)]
pub enum SymmetricCryptoKey {
    Aes256CbcKey(Aes256CbcKey),
    Aes256CbcHmacKey(Aes256CbcHmacKey),
}

impl SymmetricCryptoKey {
    // enc type 0 old static format
    const AES256_CBC_KEY_LEN: usize = 32;
    // enc type 2 old static format
    const AES256_CBC_HMAC_KEY_LEN: usize = 64;

    /// Generate a new random [SymmetricCryptoKey]
    pub fn generate(mut rng: impl rand::RngCore) -> Self {
        let mut enc_key = Box::pin(GenericArray::<u8, U32>::default());
        let mut mac_key = Box::pin(GenericArray::<u8, U32>::default());

        rng.fill(enc_key.as_mut_slice());
        rng.fill(mac_key.as_mut_slice());

        SymmetricCryptoKey::Aes256CbcHmacKey(Aes256CbcHmacKey { enc_key, mac_key })
    }

    pub fn to_encoded(&self, use_new_format: bool) -> Vec<u8> {
        match (self, use_new_format) {
            (SymmetricCryptoKey::Aes256CbcKey(key), false) => key.enc_key.to_vec(),
            (SymmetricCryptoKey::Aes256CbcHmacKey(key), false) => {
                let mut buf = Vec::with_capacity(64);
                buf.extend_from_slice(&key.enc_key);
                buf.extend_from_slice(&key.mac_key);
                buf
            }
            (_, true) => {
                let serialized_key = SerializedSymmetricCryptoKey::from(self.clone());
                let mut encoded_key = Vec::new();

                // This is safe because we are writing to Vec<u8>
                #[allow(clippy::unwrap_used)]
                ciborium::into_writer(&serialized_key, &mut encoded_key).unwrap();
                pad_key(&mut encoded_key, Self::AES256_CBC_HMAC_KEY_LEN + 1);
                encoded_key
            }
        }
    }

    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.to_encoded(false))
    }
}

impl ConstantTimeEq for SymmetricCryptoKey {
    fn ct_eq(&self, other: &SymmetricCryptoKey) -> Choice {
        match (self, other) {
            (SymmetricCryptoKey::Aes256CbcKey(a), SymmetricCryptoKey::Aes256CbcKey(b)) => {
                a.ct_eq(b)
            }
            (SymmetricCryptoKey::Aes256CbcHmacKey(a), SymmetricCryptoKey::Aes256CbcHmacKey(b)) => {
                a.ct_eq(b)
            }
            _ => Choice::from(0),
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
            let decoded_key: SerializedSymmetricCryptoKey =
                ciborium::from_reader(unpadded_value).map_err(|_| CryptoError::EncodingError)?;
            value.zeroize();
            SymmetricCryptoKey::try_from(decoded_key)
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

impl TryFrom<SerializedSymmetricCryptoKey> for SymmetricCryptoKey {
    type Error = CryptoError;

    fn try_from(value: SerializedSymmetricCryptoKey) -> Result<Self, Self::Error> {
        match value {
            SerializedSymmetricCryptoKey::Aes256CbcHmac {
                encryption_key,
                authentication_key,
            } => Ok(SymmetricCryptoKey::Aes256CbcHmacKey(Aes256CbcHmacKey {
                enc_key: Box::pin(*GenericArray::from_slice(encryption_key.as_slice())),
                mac_key: Box::pin(*GenericArray::from_slice(authentication_key.as_slice())),
            })),
            SerializedSymmetricCryptoKey::Aes256Cbc { encryption_key } => {
                Ok(SymmetricCryptoKey::Aes256CbcKey(Aes256CbcKey {
                    enc_key: Box::pin(*GenericArray::from_slice(encryption_key.as_slice())),
                }))
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "alg")]
enum SerializedSymmetricCryptoKey {
    #[serde(rename = "A256C")]
    Aes256Cbc {
        #[serde(with = "serde_bytes", rename = "ek")]
        encryption_key: Vec<u8>,
    },
    #[serde(rename = "A256C-H")]
    Aes256CbcHmac {
        #[serde(with = "serde_bytes", rename = "ek")]
        encryption_key: Vec<u8>,
        #[serde(with = "serde_bytes", rename = "ak")]
        authentication_key: Vec<u8>,
    },
}

impl From<SymmetricCryptoKey> for SerializedSymmetricCryptoKey {
    fn from(key: SymmetricCryptoKey) -> Self {
        match &key {
            SymmetricCryptoKey::Aes256CbcKey(k) => SerializedSymmetricCryptoKey::Aes256Cbc {
                encryption_key: k.enc_key.to_vec(),
            },
            SymmetricCryptoKey::Aes256CbcHmacKey(k) => {
                SerializedSymmetricCryptoKey::Aes256CbcHmac {
                    encryption_key: k.enc_key.to_vec(),
                    authentication_key: k.mac_key.to_vec(),
                }
            }
        }
    }
}
/// Pad a key to a minimum length using PKCS7-like padding
fn pad_key(key_bytes: &mut Vec<u8>, min_length: usize) {
    // at least 1 byte of padding is required
    let pad_bytes = min_length.saturating_sub(key_bytes.len()).max(1);
    let padded_length = max(min_length, key_bytes.len() + 1);
    key_bytes.resize(padded_length, pad_bytes as u8);
}

// Unpad a key
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
    fn test_encode_decode_new_symmetric_crypto_key() {
        let key = SymmetricCryptoKey::generate(rand::thread_rng());
        let encoded = key.to_encoded(true);
        let decoded = SymmetricCryptoKey::try_from(encoded).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn test_decode_new_symmetric_crypto_key() {
        let key_b64 = STANDARD.decode("o2NhbGdnQTI1NkMtSGJla1ggE59xZ8cwZ/RNny2YV/38z3QOOTsQm17jSPX+qXGxmqNiYWtYIMJwkGi9PwrnRF5aul3QKGpiR85DPwQTuRf9m6VI1gPxAQ==").unwrap();
        let key = SymmetricCryptoKey::try_from(key_b64).unwrap();
        match key {
            SymmetricCryptoKey::Aes256CbcHmacKey(_) => (),
            _ => panic!("Invalid key type"),
        }
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

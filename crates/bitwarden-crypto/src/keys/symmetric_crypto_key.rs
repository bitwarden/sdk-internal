use std::pin::Pin;

use aes::cipher::typenum::U32;
use base64::{engine::general_purpose::STANDARD, Engine};
use generic_array::GenericArray;
use rand::Rng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::key_encryptable::CryptoKey;
use crate::CryptoError;

/// Aes256CbcKey is a symmetric encryption key, consisting of one 256-bit key,
/// used to decrypt legacy type 0 encstrings. The data is not autenticated
/// so this should be used with caution, and removed where possible.
#[derive(ZeroizeOnDrop, Clone)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct Aes256CbcKey {
    // GenericArray is equivalent to [u8; N], which is a Copy type placed on the stack.
    // To keep the compiler from making stack copies when moving this struct around,
    // we use a Box to keep the values on the heap. We also pin the box to make sure
    // that the contents can't be pulled out of the box and moved
    pub(crate) enc_key: Pin<Box<GenericArray<u8, U32>>>,
}

/// Aes256CbcHmacKey is a symmetric encryption key consisting
/// of two 256-bit keys, one for encryption and one for MAC
#[derive(ZeroizeOnDrop, Clone)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct Aes256CbcHmacKey {
    // GenericArray is equivalent to [u8; N], which is a Copy type placed on the stack.
    // To keep the compiler from making stack copies when moving this struct around,
    // we use a Box to keep the values on the heap. We also pin the box to make sure
    // that the contents can't be pulled out of the box and moved
    pub(crate) enc_key: Pin<Box<GenericArray<u8, U32>>>,
    pub(crate) mac_key: Pin<Box<GenericArray<u8, U32>>>,
}

/// A symmetric encryption key. Used to encrypt and decrypt [`EncString`](crate::EncString)
#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum SymmetricCryptoKey {
    Aes256CbcKey(Aes256CbcKey),
    Aes256CbcHmacKey(Aes256CbcHmacKey),
}

impl ZeroizeOnDrop for SymmetricCryptoKey {}

impl SymmetricCryptoKey {
    const AES256_CBC_ENC_KEY_LEN: usize = 32;
    const AES256_CBC_MAC_KEY_LEN: usize = 32;
    const AES256_CBC_HMAC_KEY_LEN: usize =
        Self::AES256_CBC_ENC_KEY_LEN + Self::AES256_CBC_MAC_KEY_LEN;

    /// Generate a new random [SymmetricCryptoKey]
    /// @param rng: A random number generator
    pub fn generate(mut rng: impl rand::RngCore) -> Self {
        let mut enc_key = Box::pin(GenericArray::<u8, U32>::default());
        let mut mac_key = Box::pin(GenericArray::<u8, U32>::default());

        rng.fill(enc_key.as_mut_slice());
        rng.fill(mac_key.as_mut_slice());

        SymmetricCryptoKey::Aes256CbcHmacKey(Aes256CbcHmacKey { enc_key, mac_key })
    }

    pub fn to_base64(&self) -> Result<String, CryptoError> {
        Ok(STANDARD.encode(self.to_encoded(false)?))
    }

    pub fn to_encoded(&self, use_new_format: bool) -> Result<Vec<u8>, CryptoError> {
        match (self, use_new_format) {
            (SymmetricCryptoKey::Aes256CbcKey(key), false) => Ok(key.enc_key.to_vec()),
            (SymmetricCryptoKey::Aes256CbcHmacKey(key), false) => {
                let mut buf = Vec::with_capacity(64);
                buf.extend_from_slice(&key.enc_key);
                buf.extend_from_slice(&key.mac_key);
                Ok(buf)
            }
            (_, true) => {
                let serialized_key = SerializedSymmetricCryptoKey::from(self.clone());
                let encoded_key =
                    rmp_serde::to_vec(&serialized_key).map_err(|_| CryptoError::EncodingError)?;
                let padded_key = pad_key(encoded_key.as_slice(), Self::AES256_CBC_HMAC_KEY_LEN + 1);
                Ok(padded_key)
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
enum SymmetricCryptoKeyAlgorithm {
    #[serde(rename = "aes256-cbc")]
    Aes256Cbc,
    #[serde(rename = "aes256-cbc-hmac")]
    Aes256CbcHmac,
}

#[derive(Clone, Serialize, Deserialize)]
struct SerializedSymmetricCryptoKey {
    pub key_algorithm: SymmetricCryptoKeyAlgorithm,
    #[serde(with = "serde_bytes")]
    pub key_data: Vec<u8>,
}

impl From<SymmetricCryptoKey> for SerializedSymmetricCryptoKey {
    fn from(key: SymmetricCryptoKey) -> Self {
        SerializedSymmetricCryptoKey {
            key_algorithm: match key {
                SymmetricCryptoKey::Aes256CbcKey(_) => SymmetricCryptoKeyAlgorithm::Aes256Cbc,
                SymmetricCryptoKey::Aes256CbcHmacKey(_) => {
                    SymmetricCryptoKeyAlgorithm::Aes256CbcHmac
                }
            },
            key_data: match &key {
                SymmetricCryptoKey::Aes256CbcKey(key) => key.enc_key.to_vec(),
                SymmetricCryptoKey::Aes256CbcHmacKey(key) => {
                    let mut buf = Vec::with_capacity(64);
                    buf.extend_from_slice(&key.enc_key);
                    buf.extend_from_slice(&key.mac_key);
                    buf
                }
            },
        }
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
        if value.len() == Self::AES256_CBC_HMAC_KEY_LEN {
            let mut enc_key = Box::pin(GenericArray::<u8, U32>::default());
            let mut mac_key = Box::pin(GenericArray::<u8, U32>::default());

            enc_key.copy_from_slice(&value[..Self::AES256_CBC_ENC_KEY_LEN]);
            mac_key.copy_from_slice(&value[Self::AES256_CBC_ENC_KEY_LEN..]);
            value.zeroize();

            Ok(SymmetricCryptoKey::Aes256CbcHmacKey(Aes256CbcHmacKey {
                enc_key,
                mac_key,
            }))
        } else if value.len() == Self::AES256_CBC_ENC_KEY_LEN {
            let mut enc_key = Box::pin(GenericArray::<u8, U32>::default());
            enc_key.copy_from_slice(&value[..Self::AES256_CBC_ENC_KEY_LEN]);
            value.zeroize();

            Ok(SymmetricCryptoKey::Aes256CbcKey(Aes256CbcKey { enc_key }))
        } else if value.len() > Self::AES256_CBC_ENC_KEY_LEN {
            let unpadded_value = zeroize::Zeroizing::new(unpad_key(value));
            let encoded_key: SerializedSymmetricCryptoKey =
                rmp_serde::from_slice(unpadded_value.as_slice())
                    .map_err(|_| CryptoError::EncodingError)?;
            value.zeroize();

            match encoded_key.key_algorithm {
                SymmetricCryptoKeyAlgorithm::Aes256CbcHmac => {
                    let mut enc_key = Box::pin(GenericArray::<u8, U32>::default());
                    let mut mac_key = Box::pin(GenericArray::<u8, U32>::default());
                    enc_key.copy_from_slice(&encoded_key.key_data[..32]);
                    mac_key.copy_from_slice(&encoded_key.key_data[32..]);
                    Ok(SymmetricCryptoKey::Aes256CbcHmacKey(Aes256CbcHmacKey {
                        enc_key,
                        mac_key,
                    }))
                }
                _ => Err(CryptoError::InvalidKey),
            }
        } else {
            Err(CryptoError::InvalidKey)
        }
    }
}

/// Pad a key to a minimum length;
/// The first byte describes the number (N) of subsequently following null bytes
/// Next, there are N null bytes
/// Finally, the key bytes are appended
fn pad_key(key_bytes: &[u8], min_length: usize) -> Vec<u8> {
    let null_bytes = min_length.saturating_sub(1).saturating_sub(key_bytes.len());
    let mut padded_key = Vec::with_capacity(min_length);
    padded_key.extend_from_slice(&[null_bytes as u8]);
    padded_key.extend_from_slice(vec![0u8; null_bytes].as_slice());
    padded_key.extend_from_slice(key_bytes);
    padded_key
}

// Unpad a key that was padded with pad_key
fn unpad_key(key_bytes: &[u8]) -> Vec<u8> {
    let null_bytes = key_bytes[0] as usize;
    key_bytes[1 + null_bytes..].to_vec()
}

impl CryptoKey for SymmetricCryptoKey {}

// We manually implement these to make sure we don't print any sensitive data
#[cfg(not(test))]
impl std::fmt::Debug for SymmetricCryptoKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymmetricCryptoKey").finish()
    }
}

#[cfg(test)]
pub fn derive_symmetric_key(name: &str) -> SymmetricCryptoKey {
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
        let key = derive_symmetric_key("test");
        let key2 = SymmetricCryptoKey::try_from(key.to_base64().unwrap()).unwrap();

        assert_eq!(key, key2);

        let key = "UY4B5N4DA4UisCNClgZtRr6VLy9ZF5BXXC7cDZRqourKi4ghEMgISbCsubvgCkHf5DZctQjVot11/vVvN9NNHQ==".to_string();
        let key2 = SymmetricCryptoKey::try_from(key.clone()).unwrap();
        assert_eq!(key, key2.to_base64().unwrap());
    }

    #[test]
    fn test_decode_new_symmetric_crypto_key() {
        let key_b64 = STANDARD.decode("AJKvYWVzMjU2LWNiYy1obWFjxEDzAGOkqf/KbhmURQvE3ZBFRedoJAnHerX+9LGE2lWa/tLPMNhajQLZOLNLEMyW5YRRbwCf1XE1UParuHXc7pAH").unwrap();
        let key = SymmetricCryptoKey::try_from(key_b64).unwrap();
        match key {
            SymmetricCryptoKey::Aes256CbcHmacKey(_) => (),
            _ => panic!("Invalid key type"),
        }
    }

    #[test]
    fn test_pad_unpad_key_63() {
        let key_bytes = vec![1u8; 63];
        let mut encoded_bytes = vec![1u8; 65];
        encoded_bytes[0] = 1;
        encoded_bytes[1] = 0;
        let padded_key = pad_key(key_bytes.as_slice(), 65);
        assert_eq!(encoded_bytes, padded_key);
        let unpadded_key = unpad_key(&padded_key);
        assert_eq!(key_bytes, unpadded_key);
    }

    #[test]
    fn test_pad_unpad_key_64() {
        let key_bytes = vec![1u8; 64];
        let mut encoded_bytes = vec![1u8; 65];
        encoded_bytes[0] = 0;
        let padded_key = pad_key(key_bytes.as_slice(), 65);
        assert_eq!(encoded_bytes, padded_key);
        let unpadded_key = unpad_key(&padded_key);
        assert_eq!(key_bytes, unpadded_key);
    }

    #[test]
    fn test_pad_unpad_key_65() {
        let key_bytes = vec![1u8; 65];
        let mut encoded_bytes = vec![1u8; 66];
        encoded_bytes[0] = 0;
        let padded_key = pad_key(key_bytes.as_slice(), 65);
        assert_eq!(encoded_bytes, padded_key);
        let unpadded_key = unpad_key(&padded_key);
        assert_eq!(key_bytes, unpadded_key);
    }
}

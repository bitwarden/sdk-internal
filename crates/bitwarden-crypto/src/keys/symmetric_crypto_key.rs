use std::pin::Pin;

use aes::cipher::typenum::U32;
use base64::{engine::general_purpose::STANDARD, Engine};
use generic_array::GenericArray;
use rand::Rng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[cfg(not(test))]
use super::master_key::KdfDerivedKeymaterial;
use super::{key_encryptable::CryptoKey, key_hash::KeyHashData};
use crate::CryptoError;

// GenericArray is equivalent to [u8; N], which is a Copy type placed on the stack.
// To keep the compiler from making stack copies when moving this struct around,
// we use a Box to keep the values on the heap. We also pin the box to make sure
// that the contents can't be pulled out of the box and moved
#[derive(Zeroize, Clone)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct Aes256CbcKey {
    pub(crate) encryption_key: Pin<Box<GenericArray<u8, U32>>>,
}

#[derive(Zeroize, Clone)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct Aes256CbcHmacKey {
    pub(crate) encryption_key: Pin<Box<GenericArray<u8, U32>>>,
    pub(crate) mac_key: Pin<Box<GenericArray<u8, U32>>>,
}

#[derive(Zeroize, Clone)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct XChaCha20Poly1305Key {
    pub(crate) encryption_key: Pin<Box<GenericArray<u8, U32>>>,
}

/// A symmetric encryption key. Used to encrypt and decrypt [`EncString`](crate::EncString)
#[derive(Zeroize, Clone)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum SymmetricCryptoKey {
    Aes256CbcKey(Aes256CbcKey),
    Aes256CbcHmacKey(Aes256CbcHmacKey),
    XChaCha20Poly1305Key(XChaCha20Poly1305Key),
}

impl Drop for SymmetricCryptoKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl KeyHashData for SymmetricCryptoKey {
    fn hash_data(&self) -> Vec<u8> {
        match &self {
            SymmetricCryptoKey::Aes256CbcKey(key) => key.encryption_key.to_vec(),
            SymmetricCryptoKey::Aes256CbcHmacKey(key) => {
                let mut buf = Vec::with_capacity(64);
                buf.extend_from_slice(&key.encryption_key);
                buf.extend_from_slice(&key.mac_key);
                buf
            }
            SymmetricCryptoKey::XChaCha20Poly1305Key(key) => key.encryption_key.to_vec(),
        }
    }
}

impl zeroize::ZeroizeOnDrop for SymmetricCryptoKey {}

impl SymmetricCryptoKey {
    const AES256_CBC_ENC_KEY_LEN: usize = 32;
    const AES256_CBC_MAC_KEY_LEN: usize = 32;
    const AES256_CBC_HMAC_KEY_LEN: usize =
        Self::AES256_CBC_ENC_KEY_LEN + Self::AES256_CBC_MAC_KEY_LEN;

    /// Generate a new random [SymmetricCryptoKey]
    /// @param rng: A random number generator
    /// @param create_aead_key: If true, generate an XChaCha20Poly1305 key, otherwise generate an AES256CbcHmacKey; currently feature flagged
    pub fn generate(mut rng: impl rand::RngCore, create_aead_key: bool) -> Self {
        if create_aead_key {
            let mut key = Box::pin(GenericArray::<u8, U32>::default());
            rng.fill(key.as_mut_slice());
            SymmetricCryptoKey::XChaCha20Poly1305Key(XChaCha20Poly1305Key {
                encryption_key: key,
            })
        } else {
            let mut encryption_key = Box::pin(GenericArray::<u8, U32>::default());
            let mut mac_key = Box::pin(GenericArray::<u8, U32>::default());

            rng.fill(encryption_key.as_mut_slice());
            rng.fill(mac_key.as_mut_slice());

            SymmetricCryptoKey::Aes256CbcHmacKey(Aes256CbcHmacKey {
                encryption_key,
                mac_key,
            })
        }
    }

    fn total_len(&self) -> usize {
        match &self {
            SymmetricCryptoKey::Aes256CbcKey(_) => 32,
            SymmetricCryptoKey::Aes256CbcHmacKey(_) => 64,
            SymmetricCryptoKey::XChaCha20Poly1305Key(_) => 32,
        }
    }

    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.to_vec())
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.total_len());

        match &self {
            SymmetricCryptoKey::Aes256CbcKey(key) => {
                buf.extend_from_slice(&key.encryption_key);
            }
            SymmetricCryptoKey::Aes256CbcHmacKey(key) => {
                buf.extend_from_slice(&key.encryption_key);
                buf.extend_from_slice(&key.mac_key);
            }
            SymmetricCryptoKey::XChaCha20Poly1305Key(key) => {
                let encoded_key = SerializedSymmetricCryptoKey {
                    key_algorithm: SymmetricCryptoKeyAlgorithm::XChaCha20Poly1305,
                    key_data: key.encryption_key.to_vec(),
                };
                let encoded_key = rmp_serde::to_vec(&encoded_key).unwrap();
                // prevent ambiguity by adding a null byte if the key is 64 bytes long
                if encoded_key.len() >= 64 {
                    buf.extend_from_slice(&[0]);
                }
                buf.extend_from_slice(&encoded_key);
            }
        }

        buf
    }
}

#[derive(Clone, Serialize, Deserialize)]
enum SymmetricCryptoKeyAlgorithm {
    Aes256Cbc,
    Aes256CbcHmac,
    XChaCha20Poly1305,
}

#[derive(Clone, Serialize, Deserialize)]
struct SerializedSymmetricCryptoKey {
    pub key_algorithm: SymmetricCryptoKeyAlgorithm,
    pub key_data: Vec<u8>,
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
            let mut encryption_key = Box::pin(GenericArray::<u8, U32>::default());
            let mut mac_key = Box::pin(GenericArray::<u8, U32>::default());

            encryption_key.copy_from_slice(&value[..Self::AES256_CBC_ENC_KEY_LEN]);
            mac_key.copy_from_slice(&value[Self::AES256_CBC_ENC_KEY_LEN..]);
            value.zeroize();

            Ok(SymmetricCryptoKey::Aes256CbcHmacKey(Aes256CbcHmacKey {
                encryption_key,
                mac_key,
            }))
        } else if value.len() == Self::AES256_CBC_ENC_KEY_LEN {
            let mut encryption_key = Box::pin(GenericArray::<u8, U32>::default());
            encryption_key.copy_from_slice(&value[..Self::AES256_CBC_ENC_KEY_LEN]);
            value.zeroize();

            Ok(SymmetricCryptoKey::Aes256CbcKey(Aes256CbcKey {
                encryption_key,
            }))
        } else {
            let mut value = value;
            // prevent ambiguity by removing a null byte if the key is 64 bytes long
            if value.len() >= 65 {
                value = &mut value[1..];
            }
            let encoded_key: SerializedSymmetricCryptoKey =
                rmp_serde::from_slice(value).map_err(|_| CryptoError::InvalidKey)?;
            value.zeroize();

            match encoded_key.key_algorithm {
                SymmetricCryptoKeyAlgorithm::XChaCha20Poly1305 => {
                    let mut encryption_key = Box::pin(GenericArray::<u8, U32>::default());
                    encryption_key.copy_from_slice(&encoded_key.key_data);

                    Ok(SymmetricCryptoKey::XChaCha20Poly1305Key(
                        XChaCha20Poly1305Key { encryption_key },
                    ))
                }
                SymmetricCryptoKeyAlgorithm::Aes256CbcHmac => {
                    let mut encryption_key = Box::pin(GenericArray::<u8, U32>::default());
                    let mut mac_key = Box::pin(GenericArray::<u8, U32>::default());
                    encryption_key.copy_from_slice(&encoded_key.key_data[..32]);
                    mac_key.copy_from_slice(&encoded_key.key_data[32..]);
                    Ok(SymmetricCryptoKey::Aes256CbcHmacKey(Aes256CbcHmacKey {
                        encryption_key,
                        mac_key,
                    }))
                }
                _ => Err(CryptoError::InvalidKey),
            }
        };
        result
    }
}

impl CryptoKey for SymmetricCryptoKey {}

// We manually implement these to make sure we don't print any sensitive data
#[cfg(not(test))]
impl std::fmt::Debug for SymmetricCryptoKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymmetricCryptoKey").finish()
    }
}

#[cfg(not(test))]
impl std::fmt::Debug for KdfDerivedKeymaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KdfDerviedKeymaterial").finish()
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
    use super::{derive_symmetric_key, SymmetricCryptoKey};

    #[test]
    fn test_symmetric_crypto_key() {
        let key = derive_symmetric_key("test");
        let key2 = SymmetricCryptoKey::try_from(key.to_base64()).unwrap();

        assert_eq!(key, key2);

        let key = "UY4B5N4DA4UisCNClgZtRr6VLy9ZF5BXXC7cDZRqourKi4ghEMgISbCsubvgCkHf5DZctQjVot11/vVvN9NNHQ==".to_string();
        let key2 = SymmetricCryptoKey::try_from(key.clone()).unwrap();
        assert_eq!(key, key2.to_base64());
    }

    #[test]
    fn test_encode_xchacha20_poly1305_key() {
        let key = SymmetricCryptoKey::generate(rand::thread_rng(), true);
        let key_vec = key.to_vec();
        let key_vec_utf8_lossy = String::from_utf8_lossy(&key_vec);
    }
}

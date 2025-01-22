use std::pin::Pin;

use aes::cipher::typenum::U32;
use base64::{engine::general_purpose::STANDARD, Engine};
use generic_array::GenericArray;
use rand::Rng;
use zeroize::Zeroize;

use super::key_encryptable::CryptoKey;
use crate::CryptoError;

#[cfg_attr(test, derive(Debug))]
pub(crate) struct KdfDerivedKeymaterial {
    pub(crate) key_material: Pin<Box<GenericArray<u8, U32>>>,
}

// GenericArray is equivalent to [u8; N], which is a Copy type placed on the stack.
// To keep the compiler from making stack copies when moving this struct around,
// we use a Box to keep the values on the heap. We also pin the box to make sure
// that the contents can't be pulled out of the box and moved
#[derive(Zeroize, Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct Aes256CbcKey {
    pub(crate) encryption_key: Pin<Box<GenericArray<u8, U32>>>,
}

#[derive(Zeroize, Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct Aes256CbcHmacKey {
    pub(crate) encryption_key: Pin<Box<GenericArray<u8, U32>>>,
    pub(crate) mac_key: Pin<Box<GenericArray<u8, U32>>>,
}

/// A symmetric encryption key. Used to encrypt and decrypt [`EncString`](crate::EncString)
#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub enum SymmetricCryptoKey {
    Aes256CbcKey(Aes256CbcKey),
    Aes256CbcHmacKey(Aes256CbcHmacKey),
}

#[cfg(test)]
impl PartialEq for SymmetricCryptoKey {
    fn eq(&self, other: &Self) -> bool {
        // this is not constant-time and should only ever be used in tests
        match (self, other) {
            (Self::Aes256CbcKey(k1), Self::Aes256CbcKey(k2)) => {
                k1.encryption_key == k2.encryption_key
            }
            (Self::Aes256CbcHmacKey(k1), Self::Aes256CbcHmacKey(k2)) => {
                k1.encryption_key == k2.encryption_key && k1.mac_key == k2.mac_key
            }
            _ => false,
        }
    }
}

impl Drop for SymmetricCryptoKey {
    fn drop(&mut self) {
        match self {
            Self::Aes256CbcKey(key) => key.zeroize(),
            Self::Aes256CbcHmacKey(key) => key.zeroize(),
        }
    }
}

impl zeroize::ZeroizeOnDrop for SymmetricCryptoKey {}

impl SymmetricCryptoKey {
    const KEY_LEN: usize = 32;
    const MAC_LEN: usize = 32;

    /// Generate a new random [SymmetricCryptoKey]
    pub fn generate(mut rng: impl rand::RngCore) -> Self {
        let mut key = Box::pin(GenericArray::<u8, U32>::default());
        let mut mac_key = Box::pin(GenericArray::<u8, U32>::default());

        rng.fill(key.as_mut_slice());
        rng.fill(mac_key.as_mut_slice());

        SymmetricCryptoKey::Aes256CbcHmacKey(Aes256CbcHmacKey {
            encryption_key: key,
            mac_key,
        })
    }

    fn total_len(&self) -> usize {
        match &self {
            SymmetricCryptoKey::Aes256CbcKey(_) => 32,
            SymmetricCryptoKey::Aes256CbcHmacKey(_) => 64,
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
        }

        buf
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
        let result = if value.len() == Self::KEY_LEN + Self::MAC_LEN {
            let mut key = Box::pin(GenericArray::<u8, U32>::default());
            let mut mac_key = Box::pin(GenericArray::<u8, U32>::default());

            key.copy_from_slice(&value[..Self::KEY_LEN]);
            mac_key.copy_from_slice(&value[Self::KEY_LEN..]);

            Ok(SymmetricCryptoKey::Aes256CbcHmacKey(Aes256CbcHmacKey {
                encryption_key: key,
                mac_key,
            }))
        } else if value.len() == Self::KEY_LEN {
            let mut key = Box::pin(GenericArray::<u8, U32>::default());

            key.copy_from_slice(&value[..Self::KEY_LEN]);

            Ok(SymmetricCryptoKey::Aes256CbcKey(Aes256CbcKey {
                encryption_key: key,
            }))
        } else {
            Err(CryptoError::InvalidKeyLen)
        };

        value.zeroize();
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

        match (&key, &key2) {
            (SymmetricCryptoKey::Aes256CbcKey(k), SymmetricCryptoKey::Aes256CbcKey(k2)) => {
                assert_eq!(k.encryption_key.to_vec(), k2.encryption_key.to_vec());
            }
            (SymmetricCryptoKey::Aes256CbcHmacKey(k), SymmetricCryptoKey::Aes256CbcHmacKey(k2)) => {
                assert_eq!(k.encryption_key.to_vec(), k2.encryption_key.to_vec());
                assert_eq!(k.mac_key.to_vec(), k2.mac_key.to_vec());
            }
            _ => panic!("Key types don't match"),
        }

        let key = "UY4B5N4DA4UisCNClgZtRr6VLy9ZF5BXXC7cDZRqourKi4ghEMgISbCsubvgCkHf5DZctQjVot11/vVvN9NNHQ==".to_string();
        let key2 = SymmetricCryptoKey::try_from(key.clone()).unwrap();
        assert_eq!(key, key2.to_base64());
    }
}

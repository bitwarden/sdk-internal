use std::pin::Pin;

use bitwarden_encoding::B64;
use coset::{CborSerializable, RegisteredLabelWithPrivate, iana::KeyOperation};
use generic_array::GenericArray;
use rand::Rng;
#[cfg(test)]
use rand::SeedableRng;
#[cfg(test)]
use rand_chacha::ChaChaRng;
#[cfg(test)]
use sha2::Digest;
use subtle::{Choice, ConstantTimeEq};
use typenum::U32;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    key_encryptable::CryptoKey,
    key_id::{KEY_ID_SIZE, KeyId},
};
use crate::{BitwardenLegacyKeyBytes, ContentFormat, CoseKeyBytes, CryptoError, cose};

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

/// [XChaCha20Poly1305Key] is a symmetric encryption key consisting
/// of one 256-bit key, and contains a key id. In contrast to the
/// [Aes256CbcKey] and [Aes256CbcHmacKey], this key type is used to create
/// CoseEncrypt0 messages.
#[derive(Zeroize, Clone)]
pub struct XChaCha20Poly1305Key {
    pub(crate) key_id: [u8; KEY_ID_SIZE],
    pub(crate) enc_key: Pin<Box<GenericArray<u8, U32>>>,
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
        let rng = rand::thread_rng();
        Self::make_aes256_cbc_hmac_key_internal(rng)
    }

    /// Generate a new random XChaCha20Poly1305 [SymmetricCryptoKey]
    pub fn make_xchacha20_poly1305_key() -> Self {
        let mut rng = rand::thread_rng();
        let mut enc_key = Box::pin(GenericArray::<u8, U32>::default());
        rng.fill(enc_key.as_mut_slice());
        Self::XChaCha20Poly1305Key(XChaCha20Poly1305Key {
            enc_key,
            key_id: KeyId::make().into(),
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
        let mut enc_key = Box::pin(GenericArray::<u8, U32>::default());
        let mut mac_key = Box::pin(GenericArray::<u8, U32>::default());

        seeded_rng.fill(enc_key.as_mut_slice());
        seeded_rng.fill(mac_key.as_mut_slice());

        SymmetricCryptoKey::Aes256CbcHmacKey(Aes256CbcHmacKey { enc_key, mac_key })
    }

    /// Creates the byte representation of the key, without any padding. This should not
    /// be used directly for creating serialized key representations, instead,
    /// [SymmetricCryptoKey::to_encoded] should be used.
    ///
    /// [SymmetricCryptoKey::Aes256CbcHmacKey] and [SymmetricCryptoKey::Aes256CbcKey] are
    /// encoded as 64 and 32 byte arrays respectively, representing the key bytes directly.
    /// [SymmetricCryptoKey::XChaCha20Poly1305Key] is encoded as a COSE key, serialized to a byte
    /// array. The COSE key can be either directly encrypted using COSE, where the content
    /// format hints an the key type, or can be represented as a byte array, if padded to be
    /// larger than the byte array representation of the other key types using the
    /// aforementioned [SymmetricCryptoKey::to_encoded] function.
    pub(crate) fn to_encoded_raw(&self) -> EncodedSymmetricKey {
        match self {
            Self::Aes256CbcKey(key) => {
                EncodedSymmetricKey::BitwardenLegacyKey(key.enc_key.to_vec().into())
            }
            Self::Aes256CbcHmacKey(key) => {
                let mut buf = Vec::with_capacity(64);
                buf.extend_from_slice(&key.enc_key);
                buf.extend_from_slice(&key.mac_key);
                EncodedSymmetricKey::BitwardenLegacyKey(buf.into())
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
                let mut enc_key = Box::pin(GenericArray::<u8, U32>::default());
                enc_key.copy_from_slice(&key.as_ref()[..Self::AES256_CBC_KEY_LEN]);
                Ok(Self::Aes256CbcKey(Aes256CbcKey { enc_key }))
            }
            EncodedSymmetricKey::BitwardenLegacyKey(key)
                if key.as_ref().len() == Self::AES256_CBC_HMAC_KEY_LEN =>
            {
                let mut enc_key = Box::pin(GenericArray::<u8, U32>::default());
                enc_key.copy_from_slice(&key.as_ref()[..32]);

                let mut mac_key = Box::pin(GenericArray::<u8, U32>::default());
                mac_key.copy_from_slice(&key.as_ref()[32..]);

                Ok(Self::Aes256CbcHmacKey(Aes256CbcHmacKey {
                    enc_key,
                    mac_key,
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
        f.debug_struct("SymmetricCryptoKey")
            .field(
                "inner_type",
                match self {
                    SymmetricCryptoKey::Aes256CbcKey(key) => key,
                    SymmetricCryptoKey::Aes256CbcHmacKey(key) => key,
                    SymmetricCryptoKey::XChaCha20Poly1305Key(key) => key,
                },
            )
            .finish()
    }
}

impl std::fmt::Debug for Aes256CbcKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Aes256CbcKey").finish()
    }
}

impl std::fmt::Debug for Aes256CbcHmacKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Aes256CbcHmacKey").finish()
    }
}

impl std::fmt::Debug for XChaCha20Poly1305Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XChaCha20Poly1305Key")
            .field("key_id", &self.key_id)
            .finish()
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
fn pad_key(key_bytes: &mut Vec<u8>, min_length: u8) {
    crate::keys::utils::pad_bytes(key_bytes, min_length as usize)
        .expect("Padding cannot fail since the min_length is < 255")
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
    use generic_array::GenericArray;
    use typenum::U32;

    use super::{SymmetricCryptoKey, derive_symmetric_key};
    use crate::{
        Aes256CbcHmacKey, Aes256CbcKey, BitwardenLegacyKeyBytes, XChaCha20Poly1305Key,
        keys::symmetric_crypto_key::{pad_key, unpad_key},
    };

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
            enc_key: Box::pin(GenericArray::<u8, U32>::default()),
        });
        let key2 = SymmetricCryptoKey::XChaCha20Poly1305Key(XChaCha20Poly1305Key {
            enc_key: Box::pin(GenericArray::<u8, U32>::default()),
            key_id: [0; 16],
        });
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_eq_variant_aes256_cbc() {
        let key1 = Aes256CbcKey {
            enc_key: Box::pin(GenericArray::<u8, U32>::clone_from_slice(
                vec![1u8; 32].as_slice(),
            )),
        };
        let key2 = Aes256CbcKey {
            enc_key: Box::pin(GenericArray::<u8, U32>::clone_from_slice(
                vec![1u8; 32].as_slice(),
            )),
        };
        let key3 = Aes256CbcKey {
            enc_key: Box::pin(GenericArray::<u8, U32>::clone_from_slice(
                vec![2u8; 32].as_slice(),
            )),
        };
        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_eq_variant_aes256_cbc_hmac() {
        let key1 = Aes256CbcHmacKey {
            enc_key: Box::pin(GenericArray::<u8, U32>::clone_from_slice(
                vec![1u8; 32].as_slice(),
            )),
            mac_key: Box::pin(GenericArray::<u8, U32>::clone_from_slice(
                vec![2u8; 32].as_slice(),
            )),
        };
        let key2 = Aes256CbcHmacKey {
            enc_key: Box::pin(GenericArray::<u8, U32>::clone_from_slice(
                vec![1u8; 32].as_slice(),
            )),
            mac_key: Box::pin(GenericArray::<u8, U32>::clone_from_slice(
                vec![2u8; 32].as_slice(),
            )),
        };
        let key3 = Aes256CbcHmacKey {
            enc_key: Box::pin(GenericArray::<u8, U32>::clone_from_slice(
                vec![3u8; 32].as_slice(),
            )),
            mac_key: Box::pin(GenericArray::<u8, U32>::clone_from_slice(
                vec![4u8; 32].as_slice(),
            )),
        };
        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_eq_variant_xchacha20_poly1305() {
        let key1 = XChaCha20Poly1305Key {
            enc_key: Box::pin(GenericArray::<u8, U32>::clone_from_slice(
                vec![1u8; 32].as_slice(),
            )),
            key_id: [0; 16],
        };
        let key2 = XChaCha20Poly1305Key {
            enc_key: Box::pin(GenericArray::<u8, U32>::clone_from_slice(
                vec![1u8; 32].as_slice(),
            )),
            key_id: [0; 16],
        };
        let key3 = XChaCha20Poly1305Key {
            enc_key: Box::pin(GenericArray::<u8, U32>::clone_from_slice(
                vec![2u8; 32].as_slice(),
            )),
            key_id: [1; 16],
        };
        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_neq_different_key_id() {
        let key1 = XChaCha20Poly1305Key {
            enc_key: Box::pin(GenericArray::<u8, U32>::default()),
            key_id: [0; 16],
        };
        let key2 = XChaCha20Poly1305Key {
            enc_key: Box::pin(GenericArray::<u8, U32>::default()),
            key_id: [1; 16],
        };
        assert_ne!(key1, key2);

        let key1 = SymmetricCryptoKey::XChaCha20Poly1305Key(key1);
        let key2 = SymmetricCryptoKey::XChaCha20Poly1305Key(key2);
        assert_ne!(key1, key2);
    }
}

//! This file contains private-use constants for COSE encoded key types and algorithms.
//! Standardized values from <https://www.iana.org/assignments/cose/cose.xhtml> should always be preferred
//! unless there is a a clear benefit, such as a clear cryptographic benefit, which MUST
//! be documented publicly.

use coset::{
    CborSerializable, ContentType, Header, Label,
    iana::{self, CoapContentFormat},
};
use generic_array::GenericArray;
use thiserror::Error;
use typenum::U32;

use crate::{
    ContentFormat, CryptoError, SymmetricCryptoKey, XChaCha20Poly1305Key,
    content_format::{Bytes, ConstContentFormat, CoseContentFormat},
    error::{EncStringParseError, EncodingError},
    xchacha20,
};

/// XChaCha20 <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03> is used over ChaCha20
/// to be able to randomly generate nonces, and to not have to worry about key wearout. Since
/// the draft was never published as an RFC, we use a private-use value for the algorithm.
pub(crate) const XCHACHA20_POLY1305: i64 = -70000;
const XCHACHA20_TEXT_PAD_BLOCK_SIZE: usize = 32;

pub(crate) const ALG_ARGON2ID13: i64 = -71000;
pub(crate) const ARGON2_SALT: i64 = -71001;
pub(crate) const ARGON2_ITERATIONS: i64 = -71002;
pub(crate) const ARGON2_MEMORY: i64 = -71003;
pub(crate) const ARGON2_PARALLELISM: i64 = -71004;

// Note: These are in the "unregistered" tree: https://datatracker.ietf.org/doc/html/rfc6838#section-3.4
// These are only used within Bitwarden, and not meant for exchange with other systems.
const CONTENT_TYPE_PADDED_UTF8: &str = "application/x.bitwarden.utf8-padded";
const CONTENT_TYPE_BITWARDEN_LEGACY_KEY: &str = "application/x.bitwarden.legacy-key";
const CONTENT_TYPE_SPKI_PUBLIC_KEY: &str = "application/x.bitwarden.spki-public-key";

// Labels
//
/// The label used for the namespace ensuring strong domain separation when using signatures.
pub(crate) const SIGNING_NAMESPACE: i64 = -80000;

/// Encrypts a plaintext message using XChaCha20Poly1305 and returns a COSE Encrypt0 message
pub(crate) fn encrypt_xchacha20_poly1305(
    plaintext: &[u8],
    key: &crate::XChaCha20Poly1305Key,
    content_format: ContentFormat,
) -> Result<Vec<u8>, CryptoError> {
    let mut plaintext = plaintext.to_vec();

    let header_builder: coset::HeaderBuilder = content_format.into();
    let mut protected_header = header_builder.key_id(key.key_id.to_vec()).build();
    // This should be adjusted to use the builder pattern once implemented in coset.
    // The related coset upstream issue is:
    // https://github.com/google/coset/issues/105
    protected_header.alg = Some(coset::Algorithm::PrivateUse(XCHACHA20_POLY1305));

    if should_pad_content(&content_format) {
        // Pad the data to a block size in order to hide plaintext length
        let min_length =
            XCHACHA20_TEXT_PAD_BLOCK_SIZE * (1 + (plaintext.len() / XCHACHA20_TEXT_PAD_BLOCK_SIZE));
        crate::keys::utils::pad_bytes(&mut plaintext, min_length)?;
    }

    let mut nonce = [0u8; xchacha20::NONCE_SIZE];
    let cose_encrypt0 = coset::CoseEncrypt0Builder::new()
        .protected(protected_header)
        .create_ciphertext(&plaintext, &[], |data, aad| {
            let ciphertext =
                crate::xchacha20::encrypt_xchacha20_poly1305(&(*key.enc_key).into(), data, aad);
            nonce = ciphertext.nonce();
            ciphertext.encrypted_bytes().to_vec()
        })
        .unprotected(coset::HeaderBuilder::new().iv(nonce.to_vec()).build())
        .build();

    cose_encrypt0
        .to_vec()
        .map_err(|err| CryptoError::EncString(EncStringParseError::InvalidCoseEncoding(err)))
}

/// Decrypts a COSE Encrypt0 message, using a XChaCha20Poly1305 key
pub(crate) fn decrypt_xchacha20_poly1305(
    cose_encrypt0_message: &[u8],
    key: &crate::XChaCha20Poly1305Key,
) -> Result<(Vec<u8>, ContentFormat), CryptoError> {
    let msg = coset::CoseEncrypt0::from_slice(cose_encrypt0_message)
        .map_err(|err| CryptoError::EncString(EncStringParseError::InvalidCoseEncoding(err)))?;

    let Some(ref alg) = msg.protected.header.alg else {
        return Err(CryptoError::EncString(
            EncStringParseError::CoseMissingAlgorithm,
        ));
    };

    if *alg != coset::Algorithm::PrivateUse(XCHACHA20_POLY1305) {
        return Err(CryptoError::WrongKeyType);
    }

    let content_format = ContentFormat::try_from(&msg.protected.header)
        .map_err(|_| CryptoError::EncString(EncStringParseError::CoseMissingContentType))?;

    if key.key_id != *msg.protected.header.key_id {
        return Err(CryptoError::WrongCoseKeyId);
    }

    let decrypted_message = msg.decrypt(&[], |data, aad| {
        let nonce = msg.unprotected.iv.as_slice();
        crate::xchacha20::decrypt_xchacha20_poly1305(
            nonce
                .try_into()
                .map_err(|_| CryptoError::InvalidNonceLength)?,
            &(*key.enc_key).into(),
            data,
            aad,
        )
    })?;

    if should_pad_content(&content_format) {
        // Unpad the data to get the original plaintext
        let data = crate::keys::utils::unpad_bytes(&decrypted_message)?;
        return Ok((data.to_vec(), content_format));
    }

    Ok((decrypted_message, content_format))
}

const SYMMETRIC_KEY: Label = Label::Int(iana::SymmetricKeyParameter::K as i64);

impl TryFrom<&coset::CoseKey> for SymmetricCryptoKey {
    type Error = CryptoError;

    fn try_from(cose_key: &coset::CoseKey) -> Result<Self, Self::Error> {
        let key_bytes = cose_key
            .params
            .iter()
            .find_map(|(label, value)| match (label, value) {
                (&SYMMETRIC_KEY, ciborium::Value::Bytes(bytes)) => Some(bytes),
                _ => None,
            })
            .ok_or(CryptoError::InvalidKey)?;
        let alg = cose_key.alg.as_ref().ok_or(CryptoError::InvalidKey)?;

        match alg {
            coset::Algorithm::PrivateUse(XCHACHA20_POLY1305) => {
                // Ensure the length is correct since `GenericArray::clone_from_slice` panics if it
                // receives the wrong length.
                if key_bytes.len() != xchacha20::KEY_SIZE {
                    return Err(CryptoError::InvalidKey);
                }
                let enc_key = Box::pin(GenericArray::<u8, U32>::clone_from_slice(key_bytes));
                let key_id = cose_key
                    .key_id
                    .as_slice()
                    .try_into()
                    .map_err(|_| CryptoError::InvalidKey)?;
                Ok(SymmetricCryptoKey::XChaCha20Poly1305Key(
                    XChaCha20Poly1305Key { enc_key, key_id },
                ))
            }
            _ => Err(CryptoError::InvalidKey),
        }
    }
}

impl From<ContentFormat> for coset::HeaderBuilder {
    fn from(format: ContentFormat) -> Self {
        let header_builder = coset::HeaderBuilder::new();

        match format {
            ContentFormat::Utf8 => {
                header_builder.content_type(CONTENT_TYPE_PADDED_UTF8.to_string())
            }
            ContentFormat::Pkcs8PrivateKey => {
                header_builder.content_format(CoapContentFormat::Pkcs8)
            }
            ContentFormat::SPKIPublicKeyDer => {
                header_builder.content_type(CONTENT_TYPE_SPKI_PUBLIC_KEY.to_string())
            }
            ContentFormat::CoseSign1 => header_builder.content_format(CoapContentFormat::CoseSign1),
            ContentFormat::CoseKey => header_builder.content_format(CoapContentFormat::CoseKey),
            ContentFormat::BitwardenLegacyKey => {
                header_builder.content_type(CONTENT_TYPE_BITWARDEN_LEGACY_KEY.to_string())
            }
            ContentFormat::OctetStream => {
                header_builder.content_format(CoapContentFormat::OctetStream)
            }
        }
    }
}

impl TryFrom<&coset::Header> for ContentFormat {
    type Error = CryptoError;

    fn try_from(header: &coset::Header) -> Result<Self, Self::Error> {
        match header.content_type.as_ref() {
            Some(ContentType::Text(format)) if format == CONTENT_TYPE_PADDED_UTF8 => {
                Ok(ContentFormat::Utf8)
            }
            Some(ContentType::Text(format)) if format == CONTENT_TYPE_BITWARDEN_LEGACY_KEY => {
                Ok(ContentFormat::BitwardenLegacyKey)
            }
            Some(ContentType::Text(format)) if format == CONTENT_TYPE_SPKI_PUBLIC_KEY => {
                Ok(ContentFormat::SPKIPublicKeyDer)
            }
            Some(ContentType::Assigned(CoapContentFormat::Pkcs8)) => {
                Ok(ContentFormat::Pkcs8PrivateKey)
            }
            Some(ContentType::Assigned(CoapContentFormat::CoseKey)) => Ok(ContentFormat::CoseKey),
            Some(ContentType::Assigned(CoapContentFormat::OctetStream)) => {
                Ok(ContentFormat::OctetStream)
            }
            _ => Err(CryptoError::EncString(
                EncStringParseError::CoseMissingContentType,
            )),
        }
    }
}

fn should_pad_content(format: &ContentFormat) -> bool {
    matches!(format, ContentFormat::Utf8)
}

/// Trait for structs that are serializable to COSE objects.
pub trait CoseSerializable<T: CoseContentFormat + ConstContentFormat> {
    /// Serializes the struct to COSE serialization
    fn to_cose(&self) -> Bytes<T>;
    /// Deserializes a serialized COSE object to a struct
    fn from_cose(bytes: &Bytes<T>) -> Result<Self, EncodingError>
    where
        Self: Sized;
}

pub(crate) fn extract_integer(
    header: &Header,
    target_label: i64,
    value_name: &str,
) -> Result<i128, CoseExtractError> {
    header
        .rest
        .iter()
        .find_map(|(label, value)| match (label, value) {
            (Label::Int(label_value), ciborium::Value::Integer(int_value))
                if *label_value == target_label =>
            {
                Some(*int_value)
            }
            _ => None,
        })
        .map(Into::into)
        .ok_or_else(|| CoseExtractError::MissingValue(value_name.to_string()))
}

pub(crate) fn extract_bytes(
    header: &Header,
    target_label: i64,
    value_name: &str,
) -> Result<Vec<u8>, CoseExtractError> {
    header
        .rest
        .iter()
        .find_map(|(label, value)| match (label, value) {
            (Label::Int(label_value), ciborium::Value::Bytes(byte_value))
                if *label_value == target_label =>
            {
                Some(byte_value.clone())
            }
            _ => None,
        })
        .ok_or(CoseExtractError::MissingValue(value_name.to_string()))
}

#[derive(Debug, Error)]
pub(crate) enum CoseExtractError {
    #[error("Missing value {0}")]
    MissingValue(String),
}

#[cfg(test)]
mod test {
    use super::*;

    const KEY_ID: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    const KEY_DATA: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const TEST_VECTOR_PLAINTEXT: &[u8] = b"Message test vector";
    const TEST_VECTOR_COSE_ENCRYPT0: &[u8] = &[
        131, 88, 28, 163, 1, 58, 0, 1, 17, 111, 3, 24, 42, 4, 80, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
        11, 12, 13, 14, 15, 161, 5, 88, 24, 78, 20, 28, 157, 180, 246, 131, 220, 82, 104, 72, 73,
        75, 43, 69, 139, 216, 167, 145, 220, 67, 168, 144, 173, 88, 35, 127, 234, 194, 83, 189,
        172, 65, 29, 156, 73, 98, 87, 231, 87, 129, 15, 235, 127, 125, 97, 211, 51, 212, 211, 2,
        13, 36, 123, 53, 12, 31, 191, 40, 13, 175,
    ];

    #[test]
    fn test_encrypt_decrypt_roundtrip_octetstream() {
        let SymmetricCryptoKey::XChaCha20Poly1305Key(ref key) =
            SymmetricCryptoKey::make_xchacha20_poly1305_key()
        else {
            panic!("Failed to create XChaCha20Poly1305Key");
        };

        let plaintext = b"Hello, world!";
        let encrypted =
            encrypt_xchacha20_poly1305(plaintext, key, ContentFormat::OctetStream).unwrap();
        let decrypted = decrypt_xchacha20_poly1305(&encrypted, key).unwrap();
        assert_eq!(decrypted, (plaintext.to_vec(), ContentFormat::OctetStream));
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_utf8() {
        let SymmetricCryptoKey::XChaCha20Poly1305Key(ref key) =
            SymmetricCryptoKey::make_xchacha20_poly1305_key()
        else {
            panic!("Failed to create XChaCha20Poly1305Key");
        };

        let plaintext = b"Hello, world!";
        let encrypted = encrypt_xchacha20_poly1305(plaintext, key, ContentFormat::Utf8).unwrap();
        let decrypted = decrypt_xchacha20_poly1305(&encrypted, key).unwrap();
        assert_eq!(decrypted, (plaintext.to_vec(), ContentFormat::Utf8));
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_pkcs8() {
        let SymmetricCryptoKey::XChaCha20Poly1305Key(ref key) =
            SymmetricCryptoKey::make_xchacha20_poly1305_key()
        else {
            panic!("Failed to create XChaCha20Poly1305Key");
        };

        let plaintext = b"Hello, world!";
        let encrypted =
            encrypt_xchacha20_poly1305(plaintext, key, ContentFormat::Pkcs8PrivateKey).unwrap();
        let decrypted = decrypt_xchacha20_poly1305(&encrypted, key).unwrap();
        assert_eq!(
            decrypted,
            (plaintext.to_vec(), ContentFormat::Pkcs8PrivateKey)
        );
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_cosekey() {
        let SymmetricCryptoKey::XChaCha20Poly1305Key(ref key) =
            SymmetricCryptoKey::make_xchacha20_poly1305_key()
        else {
            panic!("Failed to create XChaCha20Poly1305Key");
        };

        let plaintext = b"Hello, world!";
        let encrypted = encrypt_xchacha20_poly1305(plaintext, key, ContentFormat::CoseKey).unwrap();
        let decrypted = decrypt_xchacha20_poly1305(&encrypted, key).unwrap();
        assert_eq!(decrypted, (plaintext.to_vec(), ContentFormat::CoseKey));
    }

    #[test]
    fn test_decrypt_test_vector() {
        let key = XChaCha20Poly1305Key {
            key_id: KEY_ID,
            enc_key: Box::pin(*GenericArray::from_slice(&KEY_DATA)),
        };
        let decrypted = decrypt_xchacha20_poly1305(TEST_VECTOR_COSE_ENCRYPT0, &key).unwrap();
        assert_eq!(
            decrypted,
            (TEST_VECTOR_PLAINTEXT.to_vec(), ContentFormat::OctetStream)
        );
    }

    #[test]
    fn test_fail_wrong_key_id() {
        let key = XChaCha20Poly1305Key {
            key_id: [1; 16], // Different key ID
            enc_key: Box::pin(*GenericArray::from_slice(&KEY_DATA)),
        };
        assert!(matches!(
            decrypt_xchacha20_poly1305(TEST_VECTOR_COSE_ENCRYPT0, &key),
            Err(CryptoError::WrongCoseKeyId)
        ));
    }

    #[test]
    fn test_fail_wrong_algorithm() {
        let protected_header = coset::HeaderBuilder::new()
            .algorithm(iana::Algorithm::A256GCM)
            .key_id(KEY_ID.to_vec())
            .build();
        let nonce = [0u8; 16];
        let cose_encrypt0 = coset::CoseEncrypt0Builder::new()
            .protected(protected_header)
            .create_ciphertext(&[], &[], |_, _| Vec::new())
            .unprotected(coset::HeaderBuilder::new().iv(nonce.to_vec()).build())
            .build();
        let serialized_message = cose_encrypt0.to_vec().unwrap();

        let key = XChaCha20Poly1305Key {
            key_id: KEY_ID,
            enc_key: Box::pin(*GenericArray::from_slice(&KEY_DATA)),
        };
        assert!(matches!(
            decrypt_xchacha20_poly1305(&serialized_message, &key),
            Err(CryptoError::WrongKeyType)
        ));
    }
}

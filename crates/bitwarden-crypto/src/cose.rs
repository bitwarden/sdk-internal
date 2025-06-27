//! This file contains private-use constants for COSE encoded key types and algorithms.
//! Standardized values from <https://www.iana.org/assignments/cose/cose.xhtml> should always be preferred
//! unless there is a a clear benefit, such as a clear cryptographic benefit, which MUST
//! be documented publicly.

use coset::{iana, CborSerializable, Label};
use generic_array::GenericArray;
use typenum::U32;

use crate::{
    error::{EncStringParseError, EncodingError},
    xchacha20, CryptoError, SymmetricCryptoKey, XChaCha20Poly1305Key,
};

/// XChaCha20 <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03> is used over ChaCha20
/// to be able to randomly generate nonces, and to not have to worry about key wearout. Since
/// the draft was never published as an RFC, we use a private-use value for the algorithm.
pub(crate) const XCHACHA20_POLY1305: i64 = -70000;

// Labels
//
/// The label used for the namespace ensuring strong domain separation when using signatures.
pub(crate) const SIGNING_NAMESPACE: i64 = -80000;

/// Encrypts a plaintext message using XChaCha20Poly1305 and returns a COSE Encrypt0 message
pub(crate) fn encrypt_xchacha20_poly1305(
    plaintext: &[u8],
    key: &crate::XChaCha20Poly1305Key,
) -> Result<Vec<u8>, CryptoError> {
    let mut protected_header = coset::HeaderBuilder::new()
        .key_id(key.key_id.to_vec())
        .build();
    // This should be adjusted to use the builder pattern once implemented in coset.
    // The related coset upstream issue is:
    // https://github.com/google/coset/issues/105
    protected_header.alg = Some(coset::Algorithm::PrivateUse(XCHACHA20_POLY1305));

    let mut nonce = [0u8; xchacha20::NONCE_SIZE];
    let cose_encrypt0 = coset::CoseEncrypt0Builder::new()
        .protected(protected_header)
        .create_ciphertext(plaintext, &[], |data, aad| {
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
) -> Result<Vec<u8>, CryptoError> {
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
    Ok(decrypted_message)
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

/// Trait for structs that are serializable to COSE objects.
pub trait CoseSerializable {
    /// Serializes the struct to COSE serialization
    fn to_cose(&self) -> Vec<u8>;
    /// Deserializes a serialized COSE object to a struct
    fn from_cose(bytes: &[u8]) -> Result<Self, EncodingError>
    where
        Self: Sized;
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
        131, 88, 25, 162, 1, 58, 0, 1, 17, 111, 4, 80, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
        13, 14, 15, 161, 5, 88, 24, 39, 48, 159, 48, 215, 77, 21, 100, 241, 209, 216, 65, 99, 221,
        83, 63, 118, 204, 200, 175, 126, 202, 53, 33, 88, 35, 218, 136, 132, 223, 131, 246, 169,
        120, 134, 49, 56, 173, 169, 133, 232, 109, 248, 101, 59, 226, 90, 97, 210, 181, 76, 68,
        158, 159, 94, 65, 67, 23, 112, 253, 83,
    ];

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let SymmetricCryptoKey::XChaCha20Poly1305Key(ref key) =
            SymmetricCryptoKey::make_xchacha20_poly1305_key()
        else {
            panic!("Failed to create XChaCha20Poly1305Key");
        };

        let plaintext = b"Hello, world!";
        let encrypted = encrypt_xchacha20_poly1305(plaintext, key).unwrap();
        let decrypted = decrypt_xchacha20_poly1305(&encrypted, key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_test_vector() {
        let key = XChaCha20Poly1305Key {
            key_id: KEY_ID,
            enc_key: Box::pin(*GenericArray::from_slice(&KEY_DATA)),
        };
        let decrypted = decrypt_xchacha20_poly1305(TEST_VECTOR_COSE_ENCRYPT0, &key).unwrap();
        assert_eq!(decrypted, TEST_VECTOR_PLAINTEXT);
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

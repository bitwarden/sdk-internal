use std::{cmp::max, pin::Pin};

use generic_array::GenericArray;
use typenum::U32;

use super::Aes256CbcHmacKey;
use crate::{util::hkdf_expand, CryptoError, Result};

/// Stretch the given key using HKDF.
/// This can be either a kdf-derived key (PIN/Master password) or
/// a random key from key connector
pub(super) fn stretch_key(key: &Pin<Box<GenericArray<u8, U32>>>) -> Result<Aes256CbcHmacKey> {
    Ok(Aes256CbcHmacKey {
        enc_key: hkdf_expand(key, Some("enc"))?,
        mac_key: hkdf_expand(key, Some("mac"))?,
    })
}

/// Pads bytes to a minimum length using PKCS7-like padding.
/// The last N bytes of the padded bytes all have the value N. Minimum of 1 padding byte.
/// For example, padded to size 4, the value 0,0 becomes 0,0,2,2.
pub(crate) fn pad_bytes(bytes: &mut Vec<u8>, min_length: usize) {
    // at least 1 byte of padding is required
    let pad_bytes = min_length.saturating_sub(bytes.len()).max(1);
    let padded_length = max(min_length, bytes.len() + 1);
    bytes.resize(padded_length, pad_bytes as u8);
}

/// Unpads bytes that is padded using the PKCS7-like padding defined by [pad_bytes].
/// The last N bytes of the padded bytes all have the value N. Minimum of 1 padding byte.
/// For example, padded to size 4, the value 0,0 becomes 0,0,2,2.
pub(crate) fn unpad_bytes(padded_bytes: &[u8]) -> Result<&[u8], CryptoError> {
    let pad_len = *padded_bytes.last().ok_or(CryptoError::InvalidPadding)? as usize;
    if pad_len >= padded_bytes.len() {
        return Err(CryptoError::InvalidPadding);
    }
    Ok(padded_bytes[..(padded_bytes.len() - pad_len)].as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stretch_kdf_key() {
        let key = Box::pin(
            [
                31, 79, 104, 226, 150, 71, 177, 90, 194, 80, 172, 209, 17, 129, 132, 81, 138, 167,
                69, 167, 254, 149, 2, 27, 39, 197, 64, 42, 22, 195, 86, 75,
            ]
            .into(),
        );
        let stretched = stretch_key(&key).unwrap();

        assert_eq!(
            [
                111, 31, 178, 45, 238, 152, 37, 114, 143, 215, 124, 83, 135, 173, 195, 23, 142,
                134, 120, 249, 61, 132, 163, 182, 113, 197, 189, 204, 188, 21, 237, 96
            ],
            stretched.enc_key.as_slice()
        );
        assert_eq!(
            [
                221, 127, 206, 234, 101, 27, 202, 38, 86, 52, 34, 28, 78, 28, 185, 16, 48, 61, 127,
                166, 209, 247, 194, 87, 232, 26, 48, 85, 193, 249, 179, 155
            ],
            stretched.mac_key.as_slice()
        );
    }

    #[test]
    fn test_pad_bytes_roundtrip() {
        let original_bytes = vec![1u8; 10];
        let mut cloned_bytes = original_bytes.clone();
        let mut encoded_bytes = vec![1u8; 12];
        encoded_bytes[10] = 2;
        encoded_bytes[11] = 2;
        pad_bytes(&mut cloned_bytes, 12);
        assert_eq!(encoded_bytes, cloned_bytes);
        let unpadded_bytes = unpad_bytes(&cloned_bytes).unwrap();
        assert_eq!(original_bytes, unpadded_bytes);
    }
}

use std::pin::Pin;

use generic_array::{typenum::U32, GenericArray};

use super::Aes256CbcHmacKey;
use crate::{util::hkdf_expand, Result};

/// Stretch the given key using HKDF.
/// This can be either a kdf-derived key (PIN/Master password) or
/// a random key from key connector
pub(super) fn stretch_key(key: &Pin<Box<GenericArray<u8, U32>>>) -> Result<Aes256CbcHmacKey> {
    Ok(Aes256CbcHmacKey {
        enc_key: hkdf_expand(key, Some("enc"))?,
        mac_key: hkdf_expand(key, Some("mac"))?,
    })
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
}

//! XAES-256-GCM (C2SP).

use crate::{Error, backend};

/// Key length in bytes.
pub const KEY_LEN: usize = 32;
/// Nonce length in bytes.
pub const NONCE_LEN: usize = 24;
/// Authentication tag length in bytes.
pub const TAG_LEN: usize = 16;

/// Encrypts `plaintext` and authenticates it with `aad`. Returns `ciphertext || tag`.
///
/// The caller must never reuse a nonce under the same key.
pub fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    backend::xaes_256_gcm::encrypt(key, nonce, aad, plaintext)
}

/// Verifies and decrypts `ciphertext || tag`.
pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    backend::xaes_256_gcm::decrypt(key, nonce, aad, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::{array, bytes};

    const KEY: &str = "0707070707070707070707070707070707070707070707070707070707070707";
    const NONCE: &str = "090909090909090909090909090909090909090909090909";

    #[test]
    fn roundtrip() {
        let ct = encrypt(&array(KEY), &array(NONCE), b"aad", b"plaintext");
        assert_eq!(ct.len(), b"plaintext".len() + TAG_LEN);
        assert_eq!(
            decrypt(&array(KEY), &array(NONCE), b"aad", &ct),
            Ok(b"plaintext".to_vec())
        );
    }

    #[test]
    fn rejects_tampering() {
        let mut ct = encrypt(&array(KEY), &array(NONCE), b"aad", b"plaintext");
        assert_eq!(
            decrypt(&array(KEY), &array(NONCE), b"other", &ct),
            Err(Error::DecryptionFailed)
        );

        ct[0] ^= 1;
        assert_eq!(
            decrypt(&array(KEY), &array(NONCE), b"aad", &ct),
            Err(Error::DecryptionFailed)
        );
        assert_eq!(
            decrypt(&array(KEY), &array(NONCE), b"aad", &ct[..4]),
            Err(Error::DecryptionFailed)
        );
    }

    #[test]
    fn known_answer() {
        // C2SP XAES-256-GCM accumulated vector #1.
        let ct = encrypt(
            &array("0101010101010101010101010101010101010101010101010101010101010101"),
            b"ABCDEFGHIJKLMNOPQRSTUVWX",
            b"",
            b"XAES-256-GCM",
        );
        assert_eq!(
            hex::encode(ct),
            "ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271"
        );
    }

    /// Edge cases under fixed key and nonce: empty plaintext with AAD (tag only), a plaintext one
    /// byte past a block without AAD, and a multi-block plaintext with AAD.
    #[test]
    fn known_answers() {
        const KEY_42: &str = "4242424242424242424242424242424242424242424242424242424242424242";
        const NONCE_24: &str = "242424242424242424242424242424242424242424242424";

        // (aad, plaintext, ciphertext || tag), all hex
        let cases = [
            ("616164", "", "18ef199c103f13f2e1ce85cf374b9997"),
            (
                "",
                "1111111111111111111111111111111111",
                "ad5c0f01a138cecf2105b59c272f9c753a9e5deb768d43176de5ad57ce51818a\
                93",
            ),
            (
                "616164",
                "54686520717569636b2062726f776e20666f78206a756d7073206f7665722074\
                6865206c617a7920646f67",
                "e8257b30c15cb6bd5b34c6ff5949e3444d3eb310e11eef91efd172b8bf2d73f6\
                e8987bd472107d0c660e4ad8ab245fa9f6dca83a0ebfd854a7eb43",
            ),
        ];
        let (key, nonce) = (array::<KEY_LEN>(KEY_42), array::<NONCE_LEN>(NONCE_24));
        for (aad, plaintext, expected) in cases {
            let (aad, plaintext) = (bytes(aad), bytes(plaintext));
            let ciphertext = encrypt(&key, &nonce, &aad, &plaintext);
            assert_eq!(hex::encode(&ciphertext), expected);
            assert_eq!(decrypt(&key, &nonce, &aad, &ciphertext), Ok(plaintext));
        }
    }
}

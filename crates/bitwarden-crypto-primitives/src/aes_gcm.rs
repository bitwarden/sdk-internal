//! AES-256-GCM.

use crate::{Error, backend};

/// Key length in bytes.
pub const KEY_LEN: usize = 32;
/// Nonce length in bytes.
pub const NONCE_LEN: usize = 12;
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
    backend::aes_gcm::encrypt(key, nonce, aad, plaintext)
}

/// Verifies and decrypts `ciphertext || tag`.
pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    backend::aes_gcm::decrypt(key, nonce, aad, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors::{array, bytes};

    const KEY: &str = "0707070707070707070707070707070707070707070707070707070707070707";
    const NONCE: &str = "090909090909090909090909";

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
    fn known_answer_empty() {
        // Zero key, zero nonce, empty message (McGrew & Viega test case 13).
        let ct = encrypt(
            &array("0000000000000000000000000000000000000000000000000000000000000000"),
            &array("000000000000000000000000"),
            b"",
            b"",
        );
        assert_eq!(hex::encode(ct), "530f8afbc74536b9a963b4f1c4cb738b");
    }

    /// Edge cases under fixed key and nonce: empty plaintext with AAD (tag only), a plaintext one
    /// byte past a block without AAD, and a multi-block plaintext with AAD.
    #[test]
    fn known_answers() {
        const KEY_42: &str = "4242424242424242424242424242424242424242424242424242424242424242";
        const NONCE_24: &str = "242424242424242424242424";

        // (aad, plaintext, ciphertext || tag), all hex
        let cases = [
            ("616164", "", "ffee61d26a6387b554650541381cb141"),
            (
                "",
                "1111111111111111111111111111111111",
                "0480d550f8d7d72f37f933bbac2382b77d0d51d0a9e90eb0177e0ad9a1c2901b\
                b8",
            ),
            (
                "616164",
                "54686520717569636b2062726f776e20666f78206a756d7073206f7665722074\
                6865206c617a7920646f67",
                "41f9a16198b3af5d4dc840d8d245fd860a944b50dcde3d1dc384a32c33b7c767\
                6a6e71e91c3ed33cb129d70d2ce96ac992bf6360767ed0e49256a3",
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

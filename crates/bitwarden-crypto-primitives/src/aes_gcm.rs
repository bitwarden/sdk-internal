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

    const KEY: [u8; KEY_LEN] = [7; KEY_LEN];
    const NONCE: [u8; NONCE_LEN] = [9; NONCE_LEN];

    #[test]
    fn roundtrip() {
        let ct = encrypt(&KEY, &NONCE, b"aad", b"plaintext");
        assert_eq!(ct.len(), b"plaintext".len() + TAG_LEN);
        assert_eq!(
            decrypt(&KEY, &NONCE, b"aad", &ct),
            Ok(b"plaintext".to_vec())
        );
    }

    #[test]
    fn rejects_tampering() {
        let mut ct = encrypt(&KEY, &NONCE, b"aad", b"plaintext");
        assert_eq!(
            decrypt(&KEY, &NONCE, b"other", &ct),
            Err(Error::DecryptionFailed)
        );

        ct[0] ^= 1;
        assert_eq!(
            decrypt(&KEY, &NONCE, b"aad", &ct),
            Err(Error::DecryptionFailed)
        );
        assert_eq!(
            decrypt(&KEY, &NONCE, b"aad", &ct[..4]),
            Err(Error::DecryptionFailed)
        );
    }

    #[test]
    fn known_answer_empty() {
        // Zero key, zero nonce, empty message (McGrew & Viega test case 13).
        let ct = encrypt(&[0; KEY_LEN], &[0; NONCE_LEN], b"", b"");
        assert_eq!(hex::encode(ct), "530f8afbc74536b9a963b4f1c4cb738b");
    }

    /// Edge cases under fixed key and nonce: empty plaintext with AAD (tag only), a plaintext one
    /// byte past a block without AAD, and a multi-block plaintext with AAD.
    #[test]
    fn known_answers() {
        const KEY_42: [u8; KEY_LEN] = [0x42; KEY_LEN];
        const NONCE_24: [u8; NONCE_LEN] = [0x24; NONCE_LEN];
        const FOX: &[u8] = b"The quick brown fox jumps over the lazy dog";

        let cases: [(&[u8], &[u8], &str); 3] = [
            (b"aad", b"", "ffee61d26a6387b554650541381cb141"),
            (
                b"",
                &[0x11; 17],
                "0480d550f8d7d72f37f933bbac2382b77d0d51d0a9e90eb0177e0ad9a1c2901b\
                b8",
            ),
            (
                b"aad",
                FOX,
                "41f9a16198b3af5d4dc840d8d245fd860a944b50dcde3d1dc384a32c33b7c767\
                6a6e71e91c3ed33cb129d70d2ce96ac992bf6360767ed0e49256a3",
            ),
        ];
        for (aad, plaintext, expected) in cases {
            let ciphertext = encrypt(&KEY_42, &NONCE_24, aad, plaintext);
            assert_eq!(hex::encode(&ciphertext), expected);
            assert_eq!(
                decrypt(&KEY_42, &NONCE_24, aad, &ciphertext),
                Ok(plaintext.to_vec())
            );
        }
    }
}

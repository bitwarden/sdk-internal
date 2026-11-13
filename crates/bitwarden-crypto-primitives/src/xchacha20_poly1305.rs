//! XChaCha20-Poly1305.

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
    backend::xchacha20_poly1305::encrypt(key, nonce, aad, plaintext)
}

/// Verifies and decrypts `ciphertext || tag`.
pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    backend::xchacha20_poly1305::decrypt(key, nonce, aad, ciphertext)
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

    /// Edge cases under fixed key and nonce: empty plaintext with AAD (tag only), a plaintext one
    /// byte past a block without AAD, and a multi-block plaintext with AAD.
    #[test]
    fn known_answers() {
        const KEY_42: [u8; KEY_LEN] = [0x42; KEY_LEN];
        const NONCE_24: [u8; NONCE_LEN] = [0x24; NONCE_LEN];
        const FOX: &[u8] = b"The quick brown fox jumps over the lazy dog";

        let cases: [(&[u8], &[u8], &str); 3] = [
            (b"aad", b"", "bb3d3db24cbd51fdd25cb14e51c03ed8"),
            (
                b"",
                &[0x11; 17],
                "b44fc6747f355db7b33e2e2b1f991cdb23a66e8baea84463df6b29df542779ce\
                1d",
            ),
            (
                b"aad",
                FOX,
                "f136b2451f5125c5c90f5d4861ff63ea549ef69a166a19ed5241893b0e62fbb9\
                7cf4a8b455e122bc18dad68ba7eb2a903d166f31fa83074b716ac9",
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

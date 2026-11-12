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
    fn known_answer() {
        // C2SP XAES-256-GCM accumulated vector #1.
        let ct = encrypt(
            &[1; KEY_LEN],
            b"ABCDEFGHIJKLMNOPQRSTUVWX",
            b"",
            b"XAES-256-GCM",
        );
        assert_eq!(
            hex::encode(ct),
            "ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271"
        );
    }
}

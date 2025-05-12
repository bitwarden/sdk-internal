//! # XChaCha20Poly1305 operations
//!
//! Contains low level XChaCha20Poly1305 operations used by the rest of the crate.
//!
//! In most cases you should use the [EncString][crate::EncString] with
//! [KeyEncryptable][crate::KeyEncryptable] & [KeyDecryptable][crate::KeyDecryptable] instead.
//!
//! Note:
//! XChaCha20Poly1305 encrypts data, and authenticates both the cipher text and associated
//! data. This does not provide key-commitment, and assumes there can only be one key.
//!
//! If multiple keys are possible, a key-committing cipher such as
//! XChaCha20Poly1305Blake3CTX should be used: `https://github.com/bitwarden/sdk-internal/pull/41` to prevent invisible-salamander style attacks.
//! `https://eprint.iacr.org/2019/016.pdf`
//! `https://soatok.blog/2024/09/10/invisible-salamanders-are-not-what-you-think/`

use chacha20poly1305::{AeadCore, AeadInPlace, KeyInit, XChaCha20Poly1305};
use generic_array::GenericArray;
use rand::{CryptoRng, RngCore};
use typenum::Unsigned;

use crate::CryptoError;

pub(crate) const NONCE_SIZE: usize = <XChaCha20Poly1305 as AeadCore>::NonceSize::USIZE;
pub(crate) const KEY_SIZE: usize = 32;

pub(crate) struct XChaCha20Poly1305Ciphertext {
    nonce: GenericArray<u8, <XChaCha20Poly1305 as AeadCore>::NonceSize>,
    encrypted_bytes: Vec<u8>,
}

impl XChaCha20Poly1305Ciphertext {
    pub(crate) fn nonce(&self) -> [u8; NONCE_SIZE] {
        self.nonce.into()
    }

    pub(crate) fn encrypted_bytes(&self) -> &[u8] {
        &self.encrypted_bytes
    }
}

pub(crate) fn encrypt_xchacha20_poly1305(
    key: &[u8; KEY_SIZE],
    plaintext_secret_data: &[u8],
    associated_data: &[u8],
) -> XChaCha20Poly1305Ciphertext {
    let rng = rand::thread_rng();
    encrypt_xchacha20_poly1305_internal(rng, key, plaintext_secret_data, associated_data)
}

fn encrypt_xchacha20_poly1305_internal(
    rng: impl RngCore + CryptoRng,
    key: &[u8; KEY_SIZE],
    plaintext_secret_data: &[u8],
    associated_data: &[u8],
) -> XChaCha20Poly1305Ciphertext {
    let nonce = &XChaCha20Poly1305::generate_nonce(rng);
    // This buffer contains the plaintext, that will be encrypted in-place
    let mut buffer = plaintext_secret_data.to_vec();
    XChaCha20Poly1305::new(GenericArray::from_slice(key))
        .encrypt_in_place(nonce, associated_data, &mut buffer)
        .expect("encryption failed");

    XChaCha20Poly1305Ciphertext {
        nonce: *nonce,
        encrypted_bytes: buffer,
    }
}

pub(crate) fn decrypt_xchacha20_poly1305(
    nonce: &[u8; NONCE_SIZE],
    key: &[u8; KEY_SIZE],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut buffer = ciphertext.to_vec();
    XChaCha20Poly1305::new(GenericArray::from_slice(key))
        .decrypt_in_place(
            GenericArray::from_slice(nonce),
            associated_data,
            &mut buffer,
        )
        .map_err(|_| CryptoError::KeyDecrypt)?;
    Ok(buffer)
}

mod tests {
    #[cfg(test)]
    use crate::xchacha20::*;

    #[test]
    fn test_encrypt_decrypt_xchacha20() {
        let key = [0u8; KEY_SIZE];
        let plaintext_secret_data = b"My secret data";
        let authenticated_data = b"My authenticated data";
        let encrypted = encrypt_xchacha20_poly1305(&key, plaintext_secret_data, authenticated_data);
        let decrypted = decrypt_xchacha20_poly1305(
            &encrypted.nonce.into(),
            &key,
            &encrypted.encrypted_bytes,
            authenticated_data,
        )
        .unwrap();
        assert_eq!(plaintext_secret_data, decrypted.as_slice());
    }

    #[test]
    fn test_fails_when_ciphertext_changed() {
        let key = [0u8; KEY_SIZE];
        let plaintext_secret_data = b"My secret data";
        let authenticated_data = b"My authenticated data";

        let mut encrypted =
            encrypt_xchacha20_poly1305(&key, plaintext_secret_data, authenticated_data);
        encrypted.encrypted_bytes[0] = encrypted.encrypted_bytes[0].wrapping_add(1);
        let result = decrypt_xchacha20_poly1305(
            &encrypted.nonce.into(),
            &key,
            &encrypted.encrypted_bytes,
            authenticated_data,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_fails_when_associated_data_changed() {
        let key = [0u8; KEY_SIZE];
        let plaintext_secret_data = b"My secret data";
        let mut authenticated_data = b"My authenticated data".to_vec();

        let encrypted =
            encrypt_xchacha20_poly1305(&key, plaintext_secret_data, authenticated_data.as_slice());
        authenticated_data[0] = authenticated_data[0].wrapping_add(1);
        let result = decrypt_xchacha20_poly1305(
            &encrypted.nonce.into(),
            &key,
            &encrypted.encrypted_bytes,
            authenticated_data.as_slice(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_fails_when_nonce_changed() {
        let key = [0u8; KEY_SIZE];
        let plaintext_secret_data = b"My secret data";
        let authenticated_data = b"My authenticated data";

        let mut encrypted =
            encrypt_xchacha20_poly1305(&key, plaintext_secret_data, authenticated_data);
        encrypted.nonce[0] = encrypted.nonce[0].wrapping_add(1);
        let result = decrypt_xchacha20_poly1305(
            &encrypted.nonce.into(),
            &key,
            &encrypted.encrypted_bytes,
            authenticated_data,
        );
        assert!(result.is_err());
    }
}

//! # XChaCha20Poly1305 operations
//!
//! Contains low level XChaCha20Poly1305 operations used by the rest of the crate.
//!
//! In most cases you should use the [EncString][crate::EncString] with
//! [KeyEncryptable][crate::KeyEncryptable] & [KeyDecryptable][crate::KeyDecryptable] instead.

use chacha20poly1305::{AeadCore, AeadInPlace, KeyInit, XChaCha20Poly1305};
use generic_array::{typenum::U24, GenericArray};

/**
 * Note:
 * XChaCha20Poly1305 encrypts data, and authenticates both the cipher text and associated
 * data. This does not provide key-commitment, and assumes there can only be one key.
 *
 * If multiple keys are possible, a key-committing cipher such as
 * XChaCha20Poly1305Blake3CTX should be used: `https://github.com/bitwarden/sdk-internal/pull/41` to prevent invisible-salamander style attacks.
 * `https://eprint.iacr.org/2019/016.pdf`
 * `https://soatok.blog/2024/09/10/invisible-salamanders-are-not-what-you-think/`
 */
use crate::CryptoError;

#[allow(unused)]
pub(crate) fn generate_nonce() -> GenericArray<u8, U24> {
    XChaCha20Poly1305::generate_nonce(rand::thread_rng())
}

#[allow(unused)]
pub(crate) fn encrypt_xchacha20_poly1305(
    nonce: &[u8; 24],
    key: &[u8; 32],
    plaintext_secret_data: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // This buffer contains the plaintext, that will be encrypted in-place
    let mut buffer = Vec::from(plaintext_secret_data);
    XChaCha20Poly1305::new(GenericArray::from_slice(key))
        .encrypt_in_place(
            GenericArray::from_slice(nonce),
            associated_data,
            &mut buffer,
        )
        .map_err(|_| CryptoError::InvalidKey)?;
    Ok(buffer)
}

#[allow(unused)]
pub(crate) fn decrypt_xchacha20_poly1305(
    nonce: &[u8; 24],
    key: &[u8; 32],
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
        .map_err(|_| CryptoError::InvalidKey)?;
    Ok(buffer)
}

mod tests {
    #[cfg(test)]
    use crate::xchacha20::*;

    #[test]
    fn test_encrypt_decrypt_xchacha20() {
        let key = [0u8; 32];
        let plaintext_secret_data = b"My secret data";
        let authenticated_data = b"My authenticated data";
        let nonce = generate_nonce().into();

        let encrypted =
            encrypt_xchacha20_poly1305(&nonce, &key, plaintext_secret_data, authenticated_data)
                .unwrap();
        let decrypted =
            decrypt_xchacha20_poly1305(&nonce, &key, &encrypted, authenticated_data).unwrap();
        assert_eq!(plaintext_secret_data, decrypted.as_slice());
    }

    #[test]
    fn test_fails_when_ciphertext_changed() {
        let key = [0u8; 32];
        let plaintext_secret_data = b"My secret data";
        let authenticated_data = b"My authenticated data";
        let nonce = generate_nonce().into();

        let mut encrypted =
            encrypt_xchacha20_poly1305(&nonce, &key, plaintext_secret_data, authenticated_data)
                .unwrap();
        encrypted[0] = encrypted[0].wrapping_add(1);
        let result = decrypt_xchacha20_poly1305(&nonce, &key, &encrypted, authenticated_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_fails_when_associated_data_changed() {
        let key = [0u8; 32];
        let plaintext_secret_data = b"My secret data";
        let mut authenticated_data = b"My authenticated data".to_vec();
        let nonce = generate_nonce().into();

        let encrypted = encrypt_xchacha20_poly1305(
            &nonce,
            &key,
            plaintext_secret_data,
            authenticated_data.as_slice(),
        )
        .unwrap();
        authenticated_data[0] = authenticated_data[0].wrapping_add(1);
        let result = decrypt_xchacha20_poly1305(
            &nonce,
            &key,
            encrypted.as_slice(),
            authenticated_data.as_slice(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_fails_when_nonce_changed() {
        let key = [0u8; 32];
        let plaintext_secret_data = b"My secret data";
        let authenticated_data = b"My authenticated data";
        let mut nonce = generate_nonce().into();

        let encrypted =
            encrypt_xchacha20_poly1305(&nonce, &key, plaintext_secret_data, authenticated_data)
                .unwrap();
        nonce[0] = nonce[0].wrapping_add(1);
        let result = decrypt_xchacha20_poly1305(&nonce, &key, &encrypted, authenticated_data);
        assert!(result.is_err());
    }
}

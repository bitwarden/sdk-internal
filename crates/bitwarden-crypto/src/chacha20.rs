//! # XChaCha20Poly1305 operations
//!
//! Contains low level XChaCha20Poly1305 operations used by the rest of the crate.
//!
//! In most cases you should use the [EncString][crate::EncString] with
//! [KeyEncryptable][crate::KeyEncryptable] & [KeyDecryptable][crate::KeyDecryptable] instead.

use chacha20poly1305::{AeadCore, AeadInPlace, KeyInit, XChaCha20Poly1305};
use generic_array::GenericArray;

/**
 * Note:
 * XChaCha20Poly1305 encrypts data, and authenticates both the cipher text and associated data.
 * This does not provide key-commitment, and assumes there can only be one key.
 *
 * If multiple keys are possible, a key-committing cipher such as XChaCha20Poly1305Blake3CTX should be used:
 * `https://github.com/bitwarden/sdk-internal/pull/41` to prevent invisible-salamander style attacks.
 * `https://soatok.blog/2024/09/10/invisible-salamanders-are-not-what-you-think/`
 */
use crate::CryptoError;

pub struct XChaCha20Poly1305Ciphertext {
    nonce: [u8; 24],
    tag: [u8; 16],
    encrypted_data: Vec<u8>,
    authenticated_data: Vec<u8>,
}

pub(crate) fn encrypt_xchacha20_poly1305(
    key: &[u8; 32],
    plaintext_secret_data: &[u8],
    authenticated_data: &[u8],
) -> Result<XChaCha20Poly1305Ciphertext, CryptoError> {
    encrypt_xchacha20_poly1305_internal(
        rand::thread_rng(),
        key,
        plaintext_secret_data,
        authenticated_data,
    )
}

fn encrypt_xchacha20_poly1305_internal(
    rng: impl rand::CryptoRng + rand::RngCore,
    key: &[u8; 32],
    plaintext_secret_data: &[u8],
    associated_data: &[u8],
) -> Result<XChaCha20Poly1305Ciphertext, CryptoError> {
    let nonce = XChaCha20Poly1305::generate_nonce(rng);
    // This should never fail because XChaCha20Poly1305::generate_nonce always returns 24 bytes
    let nonce_slice: [u8; 24] = nonce.as_slice().try_into().expect("Nonce is 24 bytes");

    // This buffer contains the plaintext, that will be encrypted in-place
    let mut buffer = Vec::from(plaintext_secret_data);
    let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(key));

    let poly1305_tag = cipher
        .encrypt_in_place_detached(&nonce, associated_data, &mut buffer)
        .map_err(|_| CryptoError::InvalidKey)?
        .as_slice()
        .try_into()
        .expect("A poly1305 tag is 16 bytes");

    Ok(XChaCha20Poly1305Ciphertext {
        nonce: nonce_slice,
        encrypted_data: buffer,
        authenticated_data: associated_data.to_vec(),
        tag: poly1305_tag,
    })
}

pub(crate) fn decrypt_xchacha20_poly1305(
    key: &[u8; 32],
    ciphertext: &XChaCha20Poly1305Ciphertext,
) -> Result<Vec<u8>, CryptoError> {
    let associated_data = ciphertext.authenticated_data.as_slice();
    let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(key));
    let mut buffer = ciphertext.encrypted_data.clone();
    let nonce_array = GenericArray::from_slice(&ciphertext.nonce);
    let poly1305_tag = GenericArray::from_slice(&ciphertext.tag);
    cipher
        .decrypt_in_place_detached(nonce_array, associated_data, &mut buffer, &poly1305_tag)
        .map_err(|_| CryptoError::InvalidKey)?;
    Err(CryptoError::InvalidKey)
}

mod tests {
    #[cfg(test)]
    use crate::chacha20::*;

    #[test]
    fn test_encrypt_decrypt_xchacha20_poly1305_ctx() {
        let key = [0u8; 32];
        let plaintext_secret_data = b"My secret data";
        let authenticated_data = b"My authenticated data";

        let encrypted =
            encrypt_xchacha20_poly1305(&key, plaintext_secret_data, authenticated_data).unwrap();
        let decrypted = decrypt_xchacha20_poly1305(&key, &encrypted).unwrap();
        assert_eq!(plaintext_secret_data, decrypted.as_slice());
    }

    #[test]
    fn test_fails_when_ciphertext_changed() {
        let key = [0u8; 32];
        let plaintext_secret_data = b"My secret data";
        let authenticated_data = b"My authenticated data";

        let mut encrypted =
            encrypt_xchacha20_poly1305(&key, plaintext_secret_data, authenticated_data).unwrap();
        encrypted.encrypted_data[0] = encrypted.encrypted_data[0].wrapping_add(1);
        let result = decrypt_xchacha20_poly1305(&key, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_fails_when_associated_data_changed() {
        let key = [0u8; 32];
        let plaintext_secret_data = b"My secret data";
        let authenticated_data = b"My authenticated data";

        let mut encrypted =
            encrypt_xchacha20_poly1305(&key, plaintext_secret_data, authenticated_data).unwrap();
        encrypted.authenticated_data[0] = encrypted.authenticated_data[0].wrapping_add(1);
        let result = decrypt_xchacha20_poly1305(&key, &encrypted);
        assert!(result.is_err());
    }
}

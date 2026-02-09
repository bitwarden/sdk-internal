//! # AES-256-GCM operations
//!
//! Contains low level AES-256-GCM operations used by the rest of the crate.
//!
//! In most cases you should use the [EncString][crate::EncString] with
//! [KeyEncryptable][crate::KeyEncryptable] & [KeyDecryptable][crate::KeyDecryptable] instead.
//!
//! Note:
//! AES-256-GCM encrypts data, and authenticates both the cipher text and associated
//! data. This does not provide key-commitment, and assumes there can only be one key.

use aes_gcm::{AeadCore, AeadInPlace, Aes256Gcm, KeyInit};
use generic_array::GenericArray;
use rand::{CryptoRng, RngCore};
use typenum::Unsigned;

use crate::CryptoError;

pub(crate) const NONCE_SIZE: usize = <Aes256Gcm as AeadCore>::NonceSize::USIZE;
pub(crate) const KEY_SIZE: usize = 32;

pub(crate) struct Aes256GcmCiphertext {
    nonce: GenericArray<u8, <Aes256Gcm as AeadCore>::NonceSize>,
    encrypted_bytes: Vec<u8>,
}

impl Aes256GcmCiphertext {
    pub(crate) fn nonce(&self) -> [u8; NONCE_SIZE] {
        self.nonce.into()
    }

    pub(crate) fn encrypted_bytes(&self) -> &[u8] {
        &self.encrypted_bytes
    }
}

pub(crate) fn encrypt_aes256_gcm(
    key: &[u8; KEY_SIZE],
    plaintext_secret_data: &[u8],
    associated_data: &[u8],
) -> Aes256GcmCiphertext {
    let rng = rand::thread_rng();
    encrypt_aes256_gcm_internal(rng, key, plaintext_secret_data, associated_data)
}

fn encrypt_aes256_gcm_internal(
    rng: impl RngCore + CryptoRng,
    key: &[u8; KEY_SIZE],
    plaintext_secret_data: &[u8],
    associated_data: &[u8],
) -> Aes256GcmCiphertext {
    let nonce = &Aes256Gcm::generate_nonce(rng);
    let mut buffer = plaintext_secret_data.to_vec();
    Aes256Gcm::new(GenericArray::from_slice(key))
        .encrypt_in_place(nonce, associated_data, &mut buffer)
        .expect("encryption failed");

    Aes256GcmCiphertext {
        nonce: *nonce,
        encrypted_bytes: buffer,
    }
}

pub(crate) fn decrypt_aes256_gcm(
    nonce: &[u8; NONCE_SIZE],
    key: &[u8; KEY_SIZE],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut buffer = ciphertext.to_vec();
    Aes256Gcm::new(GenericArray::from_slice(key))
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
    use crate::aes_gcm::*;

    #[test]
    fn test_encrypt_decrypt_aes256_gcm() {
        let key = [0u8; KEY_SIZE];
        let plaintext_secret_data = b"My secret data";
        let authenticated_data = b"My authenticated data";
        let encrypted = encrypt_aes256_gcm(&key, plaintext_secret_data, authenticated_data);
        let decrypted = decrypt_aes256_gcm(
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

        let mut encrypted = encrypt_aes256_gcm(&key, plaintext_secret_data, authenticated_data);
        encrypted.encrypted_bytes[0] = encrypted.encrypted_bytes[0].wrapping_add(1);
        let result = decrypt_aes256_gcm(
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
            encrypt_aes256_gcm(&key, plaintext_secret_data, authenticated_data.as_slice());
        authenticated_data[0] = authenticated_data[0].wrapping_add(1);
        let result = decrypt_aes256_gcm(
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

        let mut encrypted = encrypt_aes256_gcm(&key, plaintext_secret_data, authenticated_data);
        encrypted.nonce[0] = encrypted.nonce[0].wrapping_add(1);
        let result = decrypt_aes256_gcm(
            &encrypted.nonce.into(),
            &key,
            &encrypted.encrypted_bytes,
            authenticated_data,
        );
        assert!(result.is_err());
    }
}

//! # AES-256-GCM operations
//!
//! Contains low level AES-256-GCM operations used by the rest of the crate.
//!
//! In most cases you should use the [EncString][crate::EncString] with
//! [KeyEncryptable][crate::KeyEncryptable] & [KeyDecryptable][crate::KeyDecryptable] instead.
//!
//! Note:
//! AES-256-GCM encrypts data, and authenticates both the cipher text and associated data. This does
//! not provide key-commitment, and assumes there can only be one key. It also has a short (96-bit)
//! nonce, so a fresh key must be used per (small) set of messages to avoid nonce reuse; callers
//! that derive a unique key per message (e.g. the secret-protected key envelope) satisfy this.
//!
//! If multiple keys are possible, a key-committing cipher should be used to prevent
//! invisible-salamander style attacks.
//! `https://eprint.iacr.org/2019/016.pdf`
//! `https://soatok.blog/2024/09/10/invisible-salamanders-are-not-what-you-think/`

use bitwarden_crypto_primitives::aes_gcm;
use coset::{CoseEncrypt, CoseEncrypt0};
use rand::RngExt;

use super::Aead;
use crate::CryptoError;

pub(crate) const NONCE_SIZE: usize = aes_gcm::NONCE_LEN;
pub(crate) const KEY_SIZE: usize = 32;

/// AES-256-GCM authenticated encryption with associated data.
///
/// See the [module documentation](self) for the security caveats (no key-commitment, short nonce)
/// that apply to this cipher.
pub(crate) struct Aes256Gcm;

impl Aead for Aes256Gcm {
    type Key = [u8; KEY_SIZE];
    type Ciphertext = Aes256GcmCiphertext;
    type Nonce = Aes256GcmNonce;

    fn encrypt(
        key: &Self::Key,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Self::Ciphertext {
        let buffer = aes_gcm::encrypt(key, &nonce.0, associated_data, plaintext);

        Aes256GcmCiphertext {
            encrypted_bytes: buffer,
        }
    }

    fn decrypt(
        key: &Self::Key,
        nonce: &Self::Nonce,
        ciphertext: &Self::Ciphertext,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        aes_gcm::decrypt(key, &nonce.0, associated_data, ciphertext.encrypted_bytes())
            .map_err(|_| CryptoError::KeyDecrypt)
    }
}

/// A 96-bit AES-256-GCM nonce.
///
/// AES-256-GCM has a short (96-bit) nonce, so a fresh nonce must be used for every message
/// encrypted under a given key to avoid catastrophic nonce reuse. Generate a fresh nonce with
/// [`Aes256GcmNonce::make`] for each encryption.
pub(crate) struct Aes256GcmNonce([u8; NONCE_SIZE]);

impl Aes256GcmNonce {
    /// Generates a fresh, cryptographically random nonce.
    pub(crate) fn make() -> Self {
        let mut rng = bitwarden_random::rng();
        Aes256GcmNonce(rng.random())
    }

    /// Returns the raw nonce bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Parses the nonce from a COSE message's unprotected `iv` header bytes.
    fn from_cose_iv(iv: &[u8]) -> Result<Self, CryptoError> {
        let nonce: [u8; NONCE_SIZE] = iv.try_into().map_err(|_| CryptoError::InvalidNonceLength)?;
        Ok(Aes256GcmNonce(nonce))
    }
}

/// Parses the nonce from the unprotected `iv` header of a [`CoseEncrypt`] message.
impl TryFrom<&CoseEncrypt> for Aes256GcmNonce {
    type Error = CryptoError;

    fn try_from(cose_encrypt: &CoseEncrypt) -> Result<Self, Self::Error> {
        Self::from_cose_iv(cose_encrypt.unprotected.iv.as_slice())
    }
}

/// Parses the nonce from the unprotected `iv` header of a [`CoseEncrypt0`] message.
impl TryFrom<&CoseEncrypt0> for Aes256GcmNonce {
    type Error = CryptoError;

    fn try_from(cose_encrypt0: &CoseEncrypt0) -> Result<Self, Self::Error> {
        Self::from_cose_iv(cose_encrypt0.unprotected.iv.as_slice())
    }
}

pub(crate) struct Aes256GcmCiphertext {
    encrypted_bytes: Vec<u8>,
}

impl Aes256GcmCiphertext {
    pub(crate) fn encrypted_bytes(&self) -> &[u8] {
        &self.encrypted_bytes
    }
}

/// Wraps already-encrypted bytes (e.g. read from a COSE message) so they can be passed to
/// [`Aes256Gcm::decrypt`](Aead::decrypt).
impl From<Vec<u8>> for Aes256GcmCiphertext {
    fn from(encrypted_bytes: Vec<u8>) -> Self {
        Aes256GcmCiphertext { encrypted_bytes }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(test)]
    use super::*;

    #[test]
    fn test_encrypt_decrypt_aes256_gcm() {
        let key = [0u8; KEY_SIZE];
        let nonce = Aes256GcmNonce::make();
        let plaintext_secret_data = b"My secret data";
        let authenticated_data = b"My authenticated data";
        let encrypted = Aes256Gcm::encrypt(&key, &nonce, plaintext_secret_data, authenticated_data);
        let decrypted = Aes256Gcm::decrypt(&key, &nonce, &encrypted, authenticated_data).unwrap();
        assert_eq!(plaintext_secret_data, decrypted.as_slice());
    }

    #[test]
    fn test_make_nonce_has_correct_length() {
        let nonce = Aes256GcmNonce::make();
        assert_eq!(nonce.as_bytes().len(), NONCE_SIZE);
    }

    #[test]
    fn test_fails_when_ciphertext_changed() {
        let key = [0u8; KEY_SIZE];
        let nonce = Aes256GcmNonce::make();
        let plaintext_secret_data = b"My secret data";
        let authenticated_data = b"My authenticated data";

        let mut encrypted =
            Aes256Gcm::encrypt(&key, &nonce, plaintext_secret_data, authenticated_data);
        encrypted.encrypted_bytes[0] = encrypted.encrypted_bytes[0].wrapping_add(1);
        let result = Aes256Gcm::decrypt(&key, &nonce, &encrypted, authenticated_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_fails_when_associated_data_changed() {
        let key = [0u8; KEY_SIZE];
        let nonce = Aes256GcmNonce::make();
        let plaintext_secret_data = b"My secret data";
        let mut authenticated_data = b"My authenticated data".to_vec();

        let encrypted = Aes256Gcm::encrypt(
            &key,
            &nonce,
            plaintext_secret_data,
            authenticated_data.as_slice(),
        );
        authenticated_data[0] = authenticated_data[0].wrapping_add(1);
        let result = Aes256Gcm::decrypt(&key, &nonce, &encrypted, authenticated_data.as_slice());
        assert!(result.is_err());
    }

    #[test]
    fn test_fails_when_nonce_changed() {
        let key = [0u8; KEY_SIZE];
        let nonce = Aes256GcmNonce::make();
        let plaintext_secret_data = b"My secret data";
        let authenticated_data = b"My authenticated data";

        let encrypted = Aes256Gcm::encrypt(&key, &nonce, plaintext_secret_data, authenticated_data);
        // Decrypting with a different (freshly generated) nonce must fail.
        let other_nonce = Aes256GcmNonce::make();
        let result = Aes256Gcm::decrypt(&key, &other_nonce, &encrypted, authenticated_data);
        assert!(result.is_err());
    }
}

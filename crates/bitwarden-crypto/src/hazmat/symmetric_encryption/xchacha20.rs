//! # XChaCha20-Poly1305 operations
//!
//! Contains low level XChaCha20-Poly1305 operations used by the rest of the crate.
//!
//! In most cases you should use the [EncString][crate::EncString] with
//! [KeyEncryptable][crate::KeyEncryptable] & [KeyDecryptable][crate::KeyDecryptable] instead.
//!
//! Note:
//! XChaCha20-Poly1305 encrypts data, and authenticates both the cipher text and associated data.
//! This does not provide key-commitment, and assumes there can only be one key. It has a large
//! (192-bit) nonce, so a fresh random nonce can be safely generated per message without a
//! nonce-reuse concern.
//!
//! If multiple keys are possible, a key-committing cipher such as XChaCha20Poly1305Blake3CTX should
//! be used (`https://github.com/bitwarden/sdk-internal/pull/41`) to prevent invisible-salamander
//! style attacks.
//! `https://eprint.iacr.org/2019/016.pdf`
//! `https://soatok.blog/2024/09/10/invisible-salamanders-are-not-what-you-think/`

use aes::cipher::common::Generate;
use chacha20poly1305::{
    AeadCore, AeadInOut, KeyInit, XChaCha20Poly1305 as XChaCha20Poly1305Alg, aead::Nonce,
};
use coset::{CoseEncrypt, CoseEncrypt0};
use typenum::Unsigned;

use super::Aead;
use crate::CryptoError;

pub(crate) const NONCE_SIZE: usize = <XChaCha20Poly1305Alg as AeadCore>::NonceSize::USIZE;
pub(crate) const KEY_SIZE: usize = 32;

/// XChaCha20-Poly1305 authenticated encryption with associated data.
///
/// See the [module documentation](self) for the security caveats (no key-commitment) that apply to
/// this cipher.
pub(crate) struct XChaCha20Poly1305;

impl Aead for XChaCha20Poly1305 {
    type Key = [u8; KEY_SIZE];
    type Ciphertext = XChaCha20Poly1305Ciphertext;
    type Nonce = XChaCha20Poly1305Nonce;

    fn encrypt(
        key: &Self::Key,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Self::Ciphertext {
        // This buffer contains the plaintext, that will be encrypted in-place
        let mut buffer = plaintext.to_vec();
        XChaCha20Poly1305Alg::new(key.into())
            .encrypt_in_place(&nonce.0, associated_data, &mut buffer)
            .expect("encryption failed");

        XChaCha20Poly1305Ciphertext {
            encrypted_bytes: buffer,
        }
    }

    fn decrypt(
        key: &Self::Key,
        nonce: &Self::Nonce,
        ciphertext: &Self::Ciphertext,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut buffer = ciphertext.encrypted_bytes().to_vec();
        XChaCha20Poly1305Alg::new(key.into())
            .decrypt_in_place(&nonce.0, associated_data, &mut buffer)
            .map_err(|_| CryptoError::KeyDecrypt)?;
        Ok(buffer)
    }
}

/// A 192-bit XChaCha20-Poly1305 nonce.
///
/// XChaCha20-Poly1305 has a large (192-bit) nonce, so a fresh, cryptographically random nonce can
/// be generated for every message with [`XChaCha20Poly1305Nonce::make`] without a practical risk of
/// nonce reuse.
pub(crate) struct XChaCha20Poly1305Nonce(Nonce<XChaCha20Poly1305Alg>);

impl XChaCha20Poly1305Nonce {
    /// Generates a fresh, cryptographically random nonce.
    pub(crate) fn make() -> Self {
        let mut rng = rand::rng();
        XChaCha20Poly1305Nonce(Nonce::<XChaCha20Poly1305Alg>::generate_from_rng(&mut rng))
    }

    /// Returns the raw nonce bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Parses the nonce from a COSE message's unprotected `iv` header bytes.
    fn from_cose_iv(iv: &[u8]) -> Result<Self, CryptoError> {
        let nonce: [u8; NONCE_SIZE] = iv.try_into().map_err(|_| CryptoError::InvalidNonceLength)?;
        Ok(XChaCha20Poly1305Nonce(nonce.into()))
    }
}

/// Parses the nonce from the unprotected `iv` header of a [`CoseEncrypt`] message.
impl TryFrom<&CoseEncrypt> for XChaCha20Poly1305Nonce {
    type Error = CryptoError;

    fn try_from(cose_encrypt: &CoseEncrypt) -> Result<Self, Self::Error> {
        Self::from_cose_iv(cose_encrypt.unprotected.iv.as_slice())
    }
}

/// Parses the nonce from the unprotected `iv` header of a [`CoseEncrypt0`] message.
impl TryFrom<&CoseEncrypt0> for XChaCha20Poly1305Nonce {
    type Error = CryptoError;

    fn try_from(cose_encrypt0: &CoseEncrypt0) -> Result<Self, Self::Error> {
        Self::from_cose_iv(cose_encrypt0.unprotected.iv.as_slice())
    }
}

pub(crate) struct XChaCha20Poly1305Ciphertext {
    encrypted_bytes: Vec<u8>,
}

impl XChaCha20Poly1305Ciphertext {
    pub(crate) fn encrypted_bytes(&self) -> &[u8] {
        &self.encrypted_bytes
    }
}

/// Wraps already-encrypted bytes (e.g. read from a COSE message) so they can be passed to
/// [`XChaCha20Poly1305::decrypt`](Aead::decrypt).
impl From<Vec<u8>> for XChaCha20Poly1305Ciphertext {
    fn from(encrypted_bytes: Vec<u8>) -> Self {
        XChaCha20Poly1305Ciphertext { encrypted_bytes }
    }
}

mod tests {
    #[cfg(test)]
    use super::*;

    #[test]
    fn test_encrypt_decrypt_xchacha20() {
        let key = [0u8; KEY_SIZE];
        let nonce = XChaCha20Poly1305Nonce::make();
        let plaintext_secret_data = b"My secret data";
        let authenticated_data = b"My authenticated data";
        let encrypted =
            XChaCha20Poly1305::encrypt(&key, &nonce, plaintext_secret_data, authenticated_data);
        let decrypted =
            XChaCha20Poly1305::decrypt(&key, &nonce, &encrypted, authenticated_data).unwrap();
        assert_eq!(plaintext_secret_data, decrypted.as_slice());
    }

    #[test]
    fn test_make_nonce_has_correct_length() {
        let nonce = XChaCha20Poly1305Nonce::make();
        assert_eq!(nonce.as_bytes().len(), NONCE_SIZE);
    }

    #[test]
    fn test_fails_when_ciphertext_changed() {
        let key = [0u8; KEY_SIZE];
        let nonce = XChaCha20Poly1305Nonce::make();
        let plaintext_secret_data = b"My secret data";
        let authenticated_data = b"My authenticated data";

        let mut encrypted =
            XChaCha20Poly1305::encrypt(&key, &nonce, plaintext_secret_data, authenticated_data);
        encrypted.encrypted_bytes[0] = encrypted.encrypted_bytes[0].wrapping_add(1);
        let result = XChaCha20Poly1305::decrypt(&key, &nonce, &encrypted, authenticated_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_fails_when_associated_data_changed() {
        let key = [0u8; KEY_SIZE];
        let nonce = XChaCha20Poly1305Nonce::make();
        let plaintext_secret_data = b"My secret data";
        let mut authenticated_data = b"My authenticated data".to_vec();

        let encrypted = XChaCha20Poly1305::encrypt(
            &key,
            &nonce,
            plaintext_secret_data,
            authenticated_data.as_slice(),
        );
        authenticated_data[0] = authenticated_data[0].wrapping_add(1);
        let result =
            XChaCha20Poly1305::decrypt(&key, &nonce, &encrypted, authenticated_data.as_slice());
        assert!(result.is_err());
    }

    #[test]
    fn test_fails_when_nonce_changed() {
        let key = [0u8; KEY_SIZE];
        let nonce = XChaCha20Poly1305Nonce::make();
        let plaintext_secret_data = b"My secret data";
        let authenticated_data = b"My authenticated data";

        let encrypted =
            XChaCha20Poly1305::encrypt(&key, &nonce, plaintext_secret_data, authenticated_data);
        // Decrypting with a different (freshly generated) nonce must fail.
        let other_nonce = XChaCha20Poly1305Nonce::make();
        let result = XChaCha20Poly1305::decrypt(&key, &other_nonce, &encrypted, authenticated_data);
        assert!(result.is_err());
    }
}

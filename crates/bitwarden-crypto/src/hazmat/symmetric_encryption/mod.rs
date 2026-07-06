//! # Symmetric key encryption
//!
//! Low-level ("hazmat") authenticated symmetric ciphers, exposed behind two traits:
//! - [`Aead`]: authenticated encryption *with* associated data. Implemented by AES-256-GCM
//!   ([`Aes256Gcm`]) and XChaCha20-Poly1305 ([`XChaCha20Poly1305`]).
//!
//! These are dangerous primitives that operate directly on raw key material. In most cases you
//! should use the higher-level [`safe`](crate::safe) module (e.g. the password-protected key
//! envelope or data envelope) instead.

use crate::CryptoError;
pub(crate) mod aes_gcm;
pub(crate) mod xchacha20;

#[allow(unused_imports)]
pub(crate) use aes_gcm::Aes256Gcm;
#[allow(unused_imports)]
pub(crate) use xchacha20::XChaCha20Poly1305;

/// Authenticated encryption **with** associated data (AEAD).
///
/// In addition to encrypting and authenticating the plaintext, a cipher implementing this trait
/// authenticates (but does not encrypt) caller-supplied associated data. The exact same associated
/// data must be supplied to [`decrypt`](Aead::decrypt) for authentication to succeed.
#[allow(dead_code)]
pub(crate) trait Aead {
    /// Key material used by the cipher.
    type Key;
    /// Authenticated ciphertext (the encrypted bytes). The nonce is tracked separately, by the
    /// caller.
    type Ciphertext;
    /// The per-message nonce. A fresh nonce must be supplied for every encryption under a given
    /// key.
    type Nonce;

    /// Encrypts `plaintext` under `key` with `nonce`, authenticating `associated_data` along with
    /// the ciphertext.
    ///
    /// The same `nonce` must be supplied to [`decrypt`](Aead::decrypt). A fresh nonce must be used
    /// for every message encrypted under a given key.
    fn encrypt(
        key: &Self::Key,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Self::Ciphertext;

    /// Authenticates and decrypts `ciphertext` under `key` with `nonce`, verifying
    /// `associated_data`.
    ///
    /// Returns [`CryptoError::KeyDecrypt`] if authentication fails (including a mismatch of
    /// `associated_data` or `nonce`) or the ciphertext is malformed.
    fn decrypt(
        key: &Self::Key,
        nonce: &Self::Nonce,
        ciphertext: &Self::Ciphertext,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
}

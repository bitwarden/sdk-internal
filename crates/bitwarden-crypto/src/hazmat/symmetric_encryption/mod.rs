//! # Symmetric key encryption
//!
//! Low-level ("hazmat") authenticated symmetric ciphers, exposed behind two traits:
//! - [`Aead`]: authenticated encryption *with* associated data. Implemented by AES-256-GCM
//!   ([`Aes256Gcm`]), XChaCha20-Poly1305 ([`XChaCha20Poly1305`]), and AES-256-CBC-HMAC-SHA256
//!   ([`Aes256CbcHmacSha256Aead`]).
//!
//! These are dangerous primitives that operate directly on raw key material. In most cases you
//! should use the higher-level [`safe`](crate::safe) module (e.g. the password-protected key
//! envelope or data envelope) instead.

use crate::CryptoError;
pub(crate) mod aes256_cbc;

/// An operation of one of the low-level ciphers in this module failed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SymmetricEncryptionError {
    /// The input is malformed — wrong length, invalid padding, or otherwise not a valid
    /// ciphertext for the cipher.
    FormatWrong,
    /// The integrity check (MAC / authentication tag) failed; the ciphertext, associated data,
    /// nonce/IV, and key do not match.
    IntegrityCheckFailed,
}

impl From<SymmetricEncryptionError> for CryptoError {
    fn from(_: SymmetricEncryptionError) -> Self {
        CryptoError::KeyDecrypt
    }
}
pub(crate) mod aes256_cbc_hmac_sha256_ad;
pub(crate) mod aes256_cbc_hmac_sha256_aead;
pub(crate) mod aes_gcm;
pub(crate) mod xchacha20;

#[allow(unused_imports)]
pub(crate) use aes_gcm::Aes256Gcm;
pub(crate) use aes256_cbc::Aes256Cbc;
pub(crate) use aes256_cbc_hmac_sha256_ad::Aes256CbcHmacSha256;
#[allow(unused_imports)]
pub(crate) use aes256_cbc_hmac_sha256_aead::Aes256CbcHmacSha256Aead;
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
    /// Returns [`SymmetricEncryptionError::IntegrityCheckFailed`] if authentication fails
    /// (including a mismatch of `associated_data` or `nonce`), or
    /// [`SymmetricEncryptionError::FormatWrong`] if the ciphertext is malformed.
    fn decrypt(
        key: &Self::Key,
        nonce: &Self::Nonce,
        ciphertext: &Self::Ciphertext,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, SymmetricEncryptionError>;
}

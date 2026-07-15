//! # XAES-256-GCM operations
//!
//! Contains low-level XAES-256-GCM operations used by the rest of the crate. XAES-256-GCM uses a
//! 256-bit key and a 192-bit nonce. According to the current C2SP specification, random nonces
//! support approximately 2^80 messages under one key at collision risk 2^-32.
//!
//! XAES-256-GCM is constructed from the SP 800-108r1 counter-mode KDF with CMAC-AES256 and
//! AES-256-GCM. It is neither nonce-misuse-resistant nor key-committing.
//!
//! In most cases, use higher-level APIs instead of this raw-key primitive when available.

use aes::cipher::common::Generate;
use coset::{CoseEncrypt, CoseEncrypt0};
use typenum::Unsigned;
use xaes_256_gcm::{
    Xaes256Gcm as Xaes256GcmAlg,
    aead::{AeadCore, AeadInOut, KeyInit, Nonce},
};

use super::Aead;
use crate::CryptoError;

pub(crate) const KEY_SIZE: usize = 32;
pub(crate) const NONCE_SIZE: usize = <Xaes256GcmAlg as AeadCore>::NonceSize::USIZE;

/// XAES-256-GCM authenticated encryption with associated data.
///
/// See the [module documentation](self) for the security caveats that apply to this cipher.
pub(crate) struct XAes256Gcm;

impl Aead for XAes256Gcm {
    type Key = [u8; KEY_SIZE];
    type Ciphertext = XAes256GcmCiphertext;
    type Nonce = XAes256GcmNonce;

    fn encrypt(
        key: &Self::Key,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Self::Ciphertext {
        let mut buffer = plaintext.to_vec();
        Xaes256GcmAlg::new(key.into())
            .encrypt_in_place(&nonce.0, associated_data, &mut buffer)
            .expect("encryption failed");

        XAes256GcmCiphertext {
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
        Xaes256GcmAlg::new(key.into())
            .decrypt_in_place(&nonce.0, associated_data, &mut buffer)
            .map_err(|_| CryptoError::KeyDecrypt)?;
        Ok(buffer)
    }
}

/// A 192-bit XAES-256-GCM nonce.
pub(crate) struct XAes256GcmNonce(Nonce<Xaes256GcmAlg>);

impl XAes256GcmNonce {
    /// Generates a fresh, cryptographically random nonce.
    pub(crate) fn make() -> Self {
        let mut rng = bitwarden_random::rng();
        Self(Nonce::<Xaes256GcmAlg>::generate_from_rng(&mut rng))
    }

    /// Returns the raw nonce bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Parses the nonce from a COSE message's unprotected `iv` header bytes.
    fn from_cose_iv(iv: &[u8]) -> Result<Self, CryptoError> {
        let nonce: [u8; NONCE_SIZE] = iv.try_into().map_err(|_| CryptoError::InvalidNonceLength)?;
        Ok(Self(nonce.into()))
    }
}

/// Parses the nonce from the unprotected `iv` header of a [`CoseEncrypt`] message.
impl TryFrom<&CoseEncrypt> for XAes256GcmNonce {
    type Error = CryptoError;

    fn try_from(cose_encrypt: &CoseEncrypt) -> Result<Self, Self::Error> {
        Self::from_cose_iv(cose_encrypt.unprotected.iv.as_slice())
    }
}

/// Parses the nonce from the unprotected `iv` header of a [`CoseEncrypt0`] message.
impl TryFrom<&CoseEncrypt0> for XAes256GcmNonce {
    type Error = CryptoError;

    fn try_from(cose_encrypt0: &CoseEncrypt0) -> Result<Self, Self::Error> {
        Self::from_cose_iv(cose_encrypt0.unprotected.iv.as_slice())
    }
}

pub(crate) struct XAes256GcmCiphertext {
    encrypted_bytes: Vec<u8>,
}

impl XAes256GcmCiphertext {
    pub(crate) fn encrypted_bytes(&self) -> &[u8] {
        &self.encrypted_bytes
    }
}

/// Wraps already-encrypted bytes (e.g. read from a COSE message) so they can be passed to
/// [`XAes256Gcm::decrypt`](Aead::decrypt).
impl From<Vec<u8>> for XAes256GcmCiphertext {
    fn from(encrypted_bytes: Vec<u8>) -> Self {
        Self { encrypted_bytes }
    }
}

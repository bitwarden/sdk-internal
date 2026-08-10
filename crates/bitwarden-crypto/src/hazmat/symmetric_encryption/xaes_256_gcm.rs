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

#[cfg(test)]
mod tests {
    use coset::{CoseEncrypt0Builder, CoseEncryptBuilder, HeaderBuilder};

    use super::*;

    const NONCE: &[u8; NONCE_SIZE] = b"ABCDEFGHIJKLMNOPQRSTUVWX";
    const PLAINTEXT: &[u8] = b"XAES-256-GCM";

    fn nonce(bytes: &[u8]) -> XAes256GcmNonce {
        XAes256GcmNonce::from_cose_iv(bytes).unwrap()
    }

    #[test]
    fn test_c2sp_vectors() {
        // https://c2sp.org/XAES-256-GCM: the two vectors exercise both CMAC subkey branches.
        let vectors = [
            (
                [1u8; KEY_SIZE],
                b"".as_slice(),
                "ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271",
            ),
            (
                [3u8; KEY_SIZE],
                b"c2sp.org/XAES-256-GCM".as_slice(),
                "986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d",
            ),
        ];

        for (key, associated_data, expected_ciphertext) in vectors {
            let encrypted = XAes256Gcm::encrypt(&key, &nonce(NONCE), PLAINTEXT, associated_data);
            assert_eq!(
                encrypted.encrypted_bytes(),
                hex::decode(expected_ciphertext).unwrap()
            );
        }
    }

    #[test]
    fn test_make_nonce_has_correct_length() {
        assert_eq!(XAes256GcmNonce::make().as_bytes().len(), 24);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [7u8; KEY_SIZE];
        let nonce = XAes256GcmNonce::make();
        let associated_data = b"authenticated data";
        let encrypted = XAes256Gcm::encrypt(&key, &nonce, PLAINTEXT, associated_data);

        let decrypted = XAes256Gcm::decrypt(&key, &nonce, &encrypted, associated_data).unwrap();
        assert_eq!(decrypted, PLAINTEXT);
    }

    #[test]
    fn test_authentication_failures() {
        let key = [7u8; KEY_SIZE];
        let original_nonce = nonce(NONCE);
        let associated_data = b"authenticated data";
        let encrypted = XAes256Gcm::encrypt(&key, &original_nonce, PLAINTEXT, associated_data);

        assert!(matches!(
            XAes256Gcm::decrypt(
                &[8u8; KEY_SIZE],
                &original_nonce,
                &encrypted,
                associated_data,
            ),
            Err(CryptoError::KeyDecrypt)
        ));
        assert!(matches!(
            XAes256Gcm::decrypt(
                &key,
                &original_nonce,
                &encrypted,
                b"modified authenticated data",
            ),
            Err(CryptoError::KeyDecrypt)
        ));

        let mut modified_ciphertext = encrypted.encrypted_bytes().to_vec();
        modified_ciphertext[0] ^= 1;
        assert!(matches!(
            XAes256Gcm::decrypt(
                &key,
                &original_nonce,
                &XAes256GcmCiphertext::from(modified_ciphertext),
                associated_data,
            ),
            Err(CryptoError::KeyDecrypt)
        ));

        let mut wrong_nonce = *NONCE;
        wrong_nonce[0] ^= 1;
        assert!(matches!(
            XAes256Gcm::decrypt(&key, &nonce(&wrong_nonce), &encrypted, associated_data),
            Err(CryptoError::KeyDecrypt)
        ));
    }

    #[test]
    fn test_rejects_malformed_cose_ivs() {
        let malformed_iv = vec![0; NONCE_SIZE - 1];
        let cose_encrypt = CoseEncryptBuilder::new()
            .unprotected(HeaderBuilder::new().iv(malformed_iv.clone()).build())
            .build();
        let cose_encrypt0 = CoseEncrypt0Builder::new()
            .unprotected(HeaderBuilder::new().iv(malformed_iv).build())
            .build();

        assert!(matches!(
            XAes256GcmNonce::try_from(&cose_encrypt),
            Err(CryptoError::InvalidNonceLength)
        ));
        assert!(matches!(
            XAes256GcmNonce::try_from(&cose_encrypt0),
            Err(CryptoError::InvalidNonceLength)
        ));
    }
}

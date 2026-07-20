//! # AES-256-CBC-HMAC-SHA256 operations
//!
//! An extended construction of AES-256-CBC-HMAC-SHA256. It is used when an AES256-CBC-HMAC-SHA256
//! key is used for authenticated encryption in the context of COSE. We keep the implementation
//! separately intentionally.

use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use hmac::{KeyInit, Mac};
use rand::RngExt;
use subtle::ConstantTimeEq;

use super::Aead;
use crate::CryptoError;

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

pub(crate) const NONCE_SIZE: usize = 16;
pub(crate) const ENC_KEY_SIZE: usize = 32;
pub(crate) const MAC_KEY_SIZE: usize = 32;
pub(crate) const KEY_SIZE: usize = ENC_KEY_SIZE + MAC_KEY_SIZE;
pub(crate) const MAC_SIZE: usize = 32;

/// AES-256-CBC-HMAC-SHA256 authenticated encryption with associated data.
pub(crate) struct Aes256CbcHmacSha256Aead;

impl Aead for Aes256CbcHmacSha256Aead {
    type Key = [u8; KEY_SIZE];
    type Ciphertext = Aes256CbcHmacSha256AeadCiphertext;
    type Nonce = Aes256CbcHmacSha256AeadNonce;

    fn encrypt(
        key: &Self::Key,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Self::Ciphertext {
        let (enc_key, mac_key) = split_to_subkeys(key);

        let mut encrypted_bytes =
            cbc::Encryptor::<aes::Aes256>::new(enc_key.into(), nonce.as_array().into())
                .encrypt_padded_vec::<Pkcs7>(plaintext);
        let mac =
            calculate_mac_with_aad(nonce.as_array(), &encrypted_bytes, associated_data, mac_key);
        encrypted_bytes.extend_from_slice(&mac);

        Aes256CbcHmacSha256AeadCiphertext { encrypted_bytes }
    }

    fn decrypt(
        key: &Self::Key,
        nonce: &Self::Nonce,
        ciphertext: &Self::Ciphertext,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let (enc_key, mac_key) = split_to_subkeys(key);

        let encrypted_bytes = ciphertext.encrypted_bytes();
        if encrypted_bytes.len() < MAC_SIZE {
            return Err(CryptoError::KeyDecrypt);
        }
        let (data, received_mac) = encrypted_bytes.split_at(encrypted_bytes.len() - MAC_SIZE);

        let expected_mac = calculate_mac_with_aad(nonce.as_array(), data, associated_data, mac_key);
        if expected_mac.ct_ne(received_mac).into() {
            return Err(CryptoError::KeyDecrypt);
        }

        let mut buf = data.to_vec();
        cbc::Decryptor::<aes::Aes256>::new(enc_key.into(), nonce.as_array().into())
            .decrypt_padded::<Pkcs7>(&mut buf)
            .map(|slice| slice.to_vec())
            .map_err(|_| CryptoError::KeyDecrypt)
    }
}

/// Splits the 64-byte composite key into zero-copy views over its encryption and MAC halves.
fn split_to_subkeys(key: &[u8; KEY_SIZE]) -> (&[u8; ENC_KEY_SIZE], &[u8; MAC_KEY_SIZE]) {
    let (enc_key, mac_key) = key.split_at(ENC_KEY_SIZE);
    let enc_key = enc_key
        .try_into()
        .expect("first half of a 64-byte key is always 32 bytes");
    let mac_key = mac_key
        .try_into()
        .expect("second half of a 64-byte key is always 32 bytes");
    (enc_key, mac_key)
}

/// Computes the HMAC-SHA256 MAC over `iv || len(data) || data || len(associated_data) ||
/// associated_data`, where lengths are encoded as 4-byte big-endian `u32`s.
///
/// The length prefixes remove any ambiguity about where `data` ends and `associated_data` begins,
/// since both are variable-length and directly adjacent in the MAC input.
fn calculate_mac_with_aad(
    iv: &[u8; NONCE_SIZE],
    data: &[u8],
    associated_data: &[u8],
    mac_key: &[u8; MAC_KEY_SIZE],
) -> [u8; MAC_SIZE] {
    let mut hmac =
        HmacSha256::new_from_slice(mac_key).expect("hmac new_from_slice should not fail");
    hmac.update(iv);
    hmac.update(&(data.len() as u32).to_be_bytes());
    hmac.update(data);
    hmac.update(&(associated_data.len() as u32).to_be_bytes());
    hmac.update(associated_data);
    (*hmac.finalize().into_bytes())
        .try_into()
        // This is safe because HMAC-SHA256 output size is always 32 bytes
        .expect("HMAC output size to be correct")
}

/// A 128-bit AES-256-CBC-HMAC-SHA256 IV.
///
/// A fresh, cryptographically random IV must be generated for every message encrypted under a
/// given key; use [`Aes256CbcHmacSha256AeadNonce::make`] for this.
pub(crate) struct Aes256CbcHmacSha256AeadNonce([u8; NONCE_SIZE]);

impl Aes256CbcHmacSha256AeadNonce {
    /// Generates a fresh, cryptographically random IV.
    pub(crate) fn make() -> Self {
        let mut rng = bitwarden_random::rng();
        let mut iv = [0u8; NONCE_SIZE];
        rng.fill(&mut iv);
        Aes256CbcHmacSha256AeadNonce(iv)
    }

    /// Returns the raw IV bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the IV as a fixed-size array, as required by the underlying CBC primitives.
    fn as_array(&self) -> &[u8; NONCE_SIZE] {
        &self.0
    }

    /// Parses the IV from a COSE message's unprotected `iv` header bytes.
    fn from_cose_iv(iv: &[u8]) -> Result<Self, CryptoError> {
        let iv: [u8; NONCE_SIZE] = iv.try_into().map_err(|_| CryptoError::InvalidNonceLength)?;
        Ok(Aes256CbcHmacSha256AeadNonce(iv))
    }
}

/// Parses the IV from the unprotected `iv` header of a [`coset::CoseEncrypt`] message.
impl TryFrom<&coset::CoseEncrypt> for Aes256CbcHmacSha256AeadNonce {
    type Error = CryptoError;

    fn try_from(cose_encrypt: &coset::CoseEncrypt) -> Result<Self, Self::Error> {
        Self::from_cose_iv(cose_encrypt.unprotected.iv.as_slice())
    }
}

/// Parses the IV from the unprotected `iv` header of a [`coset::CoseEncrypt0`] message.
impl TryFrom<&coset::CoseEncrypt0> for Aes256CbcHmacSha256AeadNonce {
    type Error = CryptoError;

    fn try_from(cose_encrypt0: &coset::CoseEncrypt0) -> Result<Self, Self::Error> {
        Self::from_cose_iv(cose_encrypt0.unprotected.iv.as_slice())
    }
}

pub(crate) struct Aes256CbcHmacSha256AeadCiphertext {
    encrypted_bytes: Vec<u8>,
}

impl Aes256CbcHmacSha256AeadCiphertext {
    pub(crate) fn encrypted_bytes(&self) -> &[u8] {
        &self.encrypted_bytes
    }
}

/// Wraps already-encrypted bytes (e.g. read from a COSE message) so they can be passed to
/// [`Aes256CbcHmacSha256Aead::decrypt`](Aead::decrypt).
impl From<Vec<u8>> for Aes256CbcHmacSha256AeadCiphertext {
    fn from(encrypted_bytes: Vec<u8>) -> Self {
        Aes256CbcHmacSha256AeadCiphertext { encrypted_bytes }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TESTVECTOR_PLAINTEXT: &[u8] = b"Bitwarden SDK test vector";
    const TESTVECTOR_ASSOCIATED_DATA: &[u8] = b"Bitwarden SDK test vector associated data";
    const TESTVECTOR_ENCRYPTED: &[u8] = &[
        111, 16, 33, 143, 207, 253, 106, 89, 58, 52, 145, 240, 140, 213, 149, 83, 168, 188, 122,
        57, 130, 28, 35, 182, 114, 227, 215, 250, 175, 182, 169, 102, 253, 109, 197, 48, 44, 61,
        189, 243, 17, 170, 108, 228, 96, 43, 41, 31, 205, 221, 208, 241, 18, 248, 245, 125, 217,
        130, 218, 176, 188, 244, 211, 59,
    ];

    const TESTVECTOR_KEY: [u8; KEY_SIZE] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    ];
    const TESTVECTOR_NONCE: Aes256CbcHmacSha256AeadNonce =
        Aes256CbcHmacSha256AeadNonce([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

    #[test]
    #[ignore = "Generates test vectors; run manually"]
    fn generate_test_vectors() {
        let encrypted = Aes256CbcHmacSha256Aead::encrypt(
            &TESTVECTOR_KEY,
            &TESTVECTOR_NONCE,
            TESTVECTOR_PLAINTEXT,
            TESTVECTOR_ASSOCIATED_DATA,
        );
        let decrypted = Aes256CbcHmacSha256Aead::decrypt(
            &TESTVECTOR_KEY,
            &TESTVECTOR_NONCE,
            &encrypted,
            TESTVECTOR_ASSOCIATED_DATA,
        )
        .unwrap();
        assert_eq!(decrypted, TESTVECTOR_PLAINTEXT);

        println!(
            "const TESTVECTOR_ENCRYPTED: &[u8] = &{:?};",
            encrypted.encrypted_bytes()
        );
    }

    /// Locks in the serialized format of the AEAD ciphertext (CBC ciphertext followed by the MAC
    /// over the length-prefixed input); must never break, or existing data will no longer
    /// decrypt.
    #[test]
    fn test_decrypt_testvector() {
        let encrypted = Aes256CbcHmacSha256AeadCiphertext::from(TESTVECTOR_ENCRYPTED.to_vec());

        let decrypted = Aes256CbcHmacSha256Aead::decrypt(
            &TESTVECTOR_KEY,
            &TESTVECTOR_NONCE,
            &encrypted,
            TESTVECTOR_ASSOCIATED_DATA,
        )
        .unwrap();

        assert_eq!(decrypted, TESTVECTOR_PLAINTEXT);
    }

    #[test]
    fn test_encrypt_decrypt_aes256_cbc_hmac() {
        let key = TESTVECTOR_KEY;
        let nonce = Aes256CbcHmacSha256AeadNonce::make();
        let plaintext_secret_data = b"My secret data";
        let authenticated_data = b"My authenticated data";
        let encrypted = Aes256CbcHmacSha256Aead::encrypt(
            &key,
            &nonce,
            plaintext_secret_data,
            authenticated_data,
        );
        let decrypted =
            Aes256CbcHmacSha256Aead::decrypt(&key, &nonce, &encrypted, authenticated_data).unwrap();
        assert_eq!(plaintext_secret_data, decrypted.as_slice());
    }

    #[test]
    fn test_make_nonce_has_correct_length() {
        let nonce = Aes256CbcHmacSha256AeadNonce::make();
        assert_eq!(nonce.as_bytes().len(), NONCE_SIZE);
    }

    #[test]
    fn test_fails_when_ciphertext_changed() {
        let key = TESTVECTOR_KEY;
        let nonce = Aes256CbcHmacSha256AeadNonce::make();
        let plaintext_secret_data = b"My secret data";
        let authenticated_data = b"My authenticated data";

        let mut encrypted = Aes256CbcHmacSha256Aead::encrypt(
            &key,
            &nonce,
            plaintext_secret_data,
            authenticated_data,
        );
        encrypted.encrypted_bytes[0] = encrypted.encrypted_bytes[0].wrapping_add(1);
        let result = Aes256CbcHmacSha256Aead::decrypt(&key, &nonce, &encrypted, authenticated_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_fails_when_associated_data_changed() {
        let key = TESTVECTOR_KEY;
        let nonce = Aes256CbcHmacSha256AeadNonce::make();
        let plaintext_secret_data = b"My secret data";
        let mut authenticated_data = b"My authenticated data".to_vec();

        let encrypted = Aes256CbcHmacSha256Aead::encrypt(
            &key,
            &nonce,
            plaintext_secret_data,
            authenticated_data.as_slice(),
        );
        authenticated_data[0] = authenticated_data[0].wrapping_add(1);
        let result = Aes256CbcHmacSha256Aead::decrypt(
            &key,
            &nonce,
            &encrypted,
            authenticated_data.as_slice(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_fails_when_nonce_changed() {
        let key = TESTVECTOR_KEY;
        let nonce = Aes256CbcHmacSha256AeadNonce::make();
        let plaintext_secret_data = b"My secret data";
        let authenticated_data = b"My authenticated data";

        let encrypted = Aes256CbcHmacSha256Aead::encrypt(
            &key,
            &nonce,
            plaintext_secret_data,
            authenticated_data,
        );
        // Decrypting with a different (freshly generated) nonce must fail.
        let other_nonce = Aes256CbcHmacSha256AeadNonce::make();
        let result =
            Aes256CbcHmacSha256Aead::decrypt(&key, &other_nonce, &encrypted, authenticated_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_fails_when_ciphertext_too_short() {
        let key = TESTVECTOR_KEY;
        let nonce = Aes256CbcHmacSha256AeadNonce::make();
        let truncated = Aes256CbcHmacSha256AeadCiphertext {
            encrypted_bytes: vec![0u8; MAC_SIZE - 1],
        };
        let result = Aes256CbcHmacSha256Aead::decrypt(&key, &nonce, &truncated, b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_length_prefixing_prevents_data_ad_boundary_confusion() {
        // Without length-prefixing, HMAC(iv || data || ad) for ("ab", "cd") would collide with
        // ("a", "bcd") since the concatenation is identical. Length-prefixing must prevent this.
        let mac_key = [0u8; MAC_KEY_SIZE];
        let iv = [0u8; NONCE_SIZE];
        let mac1 = calculate_mac_with_aad(&iv, b"ab", b"cd", &mac_key);
        let mac2 = calculate_mac_with_aad(&iv, b"a", b"bcd", &mac_key);
        assert_ne!(mac1, mac2);
    }
}

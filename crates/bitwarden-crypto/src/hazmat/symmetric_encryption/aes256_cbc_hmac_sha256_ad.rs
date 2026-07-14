//! # Legacy AES-256-CBC-HMAC-SHA256 operations
//!
//! Aes256CbcHmacSha256 is the construct used in type 2 EncStrings. It is an AD
//! cipher without support for additional authenticated data, but is authenticated.

use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use hmac::{KeyInit, Mac};
use subtle::ConstantTimeEq;

use super::SymmetricEncryptionError;

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

pub(crate) const IV_SIZE: usize = 16;
pub(crate) const ENC_KEY_SIZE: usize = 32;
pub(crate) const MAC_KEY_SIZE: usize = 32;
pub(crate) const KEY_SIZE: usize = ENC_KEY_SIZE + MAC_KEY_SIZE;
pub(crate) const MAC_SIZE: usize = 32;

/// The legacy AES-256-CBC-HMAC-SHA256 Encrypt-then-MAC cipher. The 64-byte composite key is the
/// AES-256-CBC encryption sub-key (first 32 bytes) followed by the HMAC-SHA256 authentication
/// sub-key (last 32 bytes).
pub(crate) struct Aes256CbcHmacSha256;

impl Aes256CbcHmacSha256 {
    /// Encrypt using AES-256 in CBC mode, returning the MAC over the IV and ciphertext along
    /// with the ciphertext.
    ///
    /// A fresh, cryptographically random IV must be supplied for every message encrypted under a
    /// given key; generating it is the caller's responsibility.
    pub(crate) fn encrypt(
        iv: &[u8; IV_SIZE],
        data_dec: &[u8],
        key: &[u8; KEY_SIZE],
    ) -> ([u8; MAC_SIZE], Vec<u8>) {
        let (enc_key, mac_key) = split_to_subkeys(key);

        let data = cbc::Encryptor::<aes::Aes256>::new(enc_key.into(), iv.into())
            .encrypt_padded_vec::<Pkcs7>(data_dec);
        let mac = calculate_mac(iv, &data, mac_key);

        (mac, data)
    }

    /// Decrypt using AES-256 in CBC mode, validating the MAC over the IV and ciphertext.
    pub(crate) fn decrypt(
        iv: &[u8; IV_SIZE],
        data: &[u8],
        mac: &[u8; MAC_SIZE],
        key: &[u8; KEY_SIZE],
    ) -> Result<Vec<u8>, SymmetricEncryptionError> {
        let (enc_key, mac_key) = split_to_subkeys(key);

        let expected_mac = calculate_mac(iv, data, mac_key);
        if expected_mac.ct_ne(mac).into() {
            return Err(SymmetricEncryptionError::IntegrityCheckFailed);
        }

        // Decrypt data in place in a copy of the ciphertext
        let mut data = data.to_vec();
        let decrypted_slice = cbc::Decryptor::<aes::Aes256>::new(enc_key.into(), iv.into())
            .decrypt_padded::<Pkcs7>(&mut data)
            .map_err(|_| SymmetricEncryptionError::FormatWrong)?;

        // Decryption returns a subslice of the buffer; truncate to the subslice length instead of
        // cloning it
        let decrypted_len = decrypted_slice.len();
        data.truncate(decrypted_len);

        Ok(data)
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

/// Generate a MAC using HMAC-SHA256 over the IV and ciphertext, without length prefixes or
/// associated data.
fn calculate_mac(iv: &[u8], data: &[u8], mac_key: &[u8; MAC_KEY_SIZE]) -> [u8; MAC_SIZE] {
    let mut hmac =
        HmacSha256::new_from_slice(mac_key).expect("hmac new_from_slice should not fail");
    hmac.update(iv);
    hmac.update(data);
    let mac: [u8; MAC_SIZE] = (*hmac.finalize().into_bytes())
        .try_into()
        // This is safe because HMAC-SHA256 output size is always 32 bytes
        .expect("HMAC output size to be correct");
    mac
}

#[cfg(test)]
mod tests {
    use super::*;

    const TESTVECTOR_PLAINTEXT: &[u8] = b"Bitwarden SDK test vector";
    const TESTVECTOR_IV: [u8; IV_SIZE] = [
        216, 218, 36, 0, 196, 186, 150, 85, 49, 147, 110, 168, 185, 227, 42, 172,
    ];
    const TESTVECTOR_MAC: [u8; MAC_SIZE] = [
        60, 78, 44, 111, 72, 233, 3, 6, 86, 250, 217, 242, 62, 229, 184, 221, 231, 150, 189, 44,
        99, 189, 220, 55, 196, 194, 101, 60, 102, 195, 149, 130,
    ];
    const TESTVECTOR_DATA: &[u8] = &[
        234, 77, 16, 15, 189, 82, 36, 188, 182, 88, 64, 67, 145, 94, 30, 178, 36, 235, 130, 67,
        255, 207, 183, 168, 73, 231, 82, 122, 193, 139, 25, 129,
    ];

    const TESTVECTOR_KEY: [u8; KEY_SIZE] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    ];

    #[test]
    #[ignore = "Generates test vectors; run manually"]
    fn generate_test_vectors() {
        let (mac, data) =
            Aes256CbcHmacSha256::encrypt(&TESTVECTOR_IV, TESTVECTOR_PLAINTEXT, &TESTVECTOR_KEY);
        let decrypted =
            Aes256CbcHmacSha256::decrypt(&TESTVECTOR_IV, &data, &mac, &TESTVECTOR_KEY).unwrap();
        assert_eq!(decrypted, TESTVECTOR_PLAINTEXT);

        println!("const TESTVECTOR_MAC: [u8; MAC_SIZE] = {mac:?};");
        println!("const TESTVECTOR_DATA: &[u8] = &{data:?};");
    }

    /// Locks in the serialized format of the type 2 (iv, mac, ciphertext) triple; must never
    /// break, or existing data will no longer decrypt.
    #[test]
    fn test_decrypt_testvector() {
        let decrypted = Aes256CbcHmacSha256::decrypt(
            &TESTVECTOR_IV,
            TESTVECTOR_DATA,
            &TESTVECTOR_MAC,
            &TESTVECTOR_KEY,
        )
        .unwrap();

        assert_eq!(decrypted, TESTVECTOR_PLAINTEXT);
    }

    #[test]
    fn test_encrypt_is_deterministic() {
        const IV: [u8; IV_SIZE] = [
            62, 0, 239, 47, 137, 95, 64, 214, 127, 91, 184, 232, 31, 9, 165, 161,
        ];

        let (_mac, data) =
            Aes256CbcHmacSha256::encrypt(&IV, "EncryptMe!".as_bytes(), &TESTVECTOR_KEY);
        assert_eq!(
            data,
            vec![
                214, 76, 187, 97, 58, 146, 212, 140, 95, 164, 177, 204, 179, 133, 172, 148
            ]
        );
    }

    #[test]
    fn test_calculate_mac() {
        const MAC_KEY: [u8; MAC_KEY_SIZE] = [
            0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128, 136, 144, 152,
            160, 168, 176, 184, 192, 200, 208, 216, 224, 232, 240, 248,
        ];
        const IV: [u8; IV_SIZE] = [
            0, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240,
        ];
        const DATA: [u8; 16] = [
            0, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240,
        ];

        let mac = calculate_mac(&IV, &DATA, &MAC_KEY);
        assert!(mac.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"EncryptMe!";

        let (mac, data) = Aes256CbcHmacSha256::encrypt(&TESTVECTOR_IV, plaintext, &TESTVECTOR_KEY);
        let decrypted =
            Aes256CbcHmacSha256::decrypt(&TESTVECTOR_IV, &data, &mac, &TESTVECTOR_KEY).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_fails_when_mac_changed() {
        let plaintext = b"EncryptMe!";

        let (mut mac, data) =
            Aes256CbcHmacSha256::encrypt(&TESTVECTOR_IV, plaintext, &TESTVECTOR_KEY);
        mac[0] = mac[0].wrapping_add(1);
        let result = Aes256CbcHmacSha256::decrypt(&TESTVECTOR_IV, &data, &mac, &TESTVECTOR_KEY);

        assert_eq!(result, Err(SymmetricEncryptionError::IntegrityCheckFailed));
    }
}

//! # Legacy AES-256-CBC operations (unauthenticated)
//!
//! Contains the legacy AES-256-CBC primitive used by the type 0 `EncString` format. The data is
//! **not authenticated**, so this must only be used to decrypt existing data, never to encrypt
//! new data.
//!
//! In most cases you should use the [EncString][crate::EncString] with
//! [KeyDecryptable][crate::KeyDecryptable] instead.

use aes::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};

use super::SymmetricEncryptionError;

pub(crate) const IV_SIZE: usize = 16;
pub(crate) const KEY_SIZE: usize = 32;

/// The unauthenticated legacy AES-256-CBC cipher.
pub(crate) struct Aes256Cbc;

impl Aes256Cbc {
    /// Decrypt using AES-256 in CBC mode.
    pub(crate) fn decrypt(
        iv: &[u8; IV_SIZE],
        ciphertext: &[u8],
        key: &[u8; KEY_SIZE],
    ) -> Result<Vec<u8>, SymmetricEncryptionError> {
        // Decrypt data in place in a copy of the ciphertext
        let mut data = ciphertext.to_vec();
        let decrypted_key_slice = cbc::Decryptor::<aes::Aes256>::new(key.into(), iv.into())
            .decrypt_padded::<Pkcs7>(&mut data)
            .map_err(|_| SymmetricEncryptionError::FormatWrong)?;

        // Decryption returns a subslice of the buffer; truncate to the subslice length instead of
        // cloning it
        let decrypted_len = decrypted_key_slice.len();
        data.truncate(decrypted_len);

        Ok(data)
    }

    /// Encrypt using AES-256 in CBC mode.
    #[cfg(test)]
    fn encrypt(iv: &[u8; IV_SIZE], plaintext: &[u8], key: &[u8; KEY_SIZE]) -> Vec<u8> {
        use aes::cipher::BlockModeEncrypt;

        cbc::Encryptor::<aes::Aes256>::new(key.into(), iv.into())
            .encrypt_padded_vec::<Pkcs7>(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_encoding::B64;

    use super::*;

    const TESTVECTOR_PLAINTEXT: &[u8] = b"Bitwarden SDK test vector";
    const TESTVECTOR_CIPHERTEXT: &[u8] = &[
        111, 16, 33, 143, 207, 253, 106, 89, 58, 52, 145, 240, 140, 213, 149, 83, 168, 188, 122,
        57, 130, 28, 35, 182, 114, 227, 215, 250, 175, 182, 169, 102,
    ];
    const TESTVECTOR_KEY: [u8; KEY_SIZE] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];
    const TESTVECTOR_IV: [u8; IV_SIZE] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    #[test]
    #[ignore = "Generates test vectors; run manually"]
    fn generate_test_vectors() {
        let ciphertext = Aes256Cbc::encrypt(&TESTVECTOR_IV, TESTVECTOR_PLAINTEXT, &TESTVECTOR_KEY);
        let decrypted = Aes256Cbc::decrypt(&TESTVECTOR_IV, &ciphertext, &TESTVECTOR_KEY).unwrap();
        assert_eq!(decrypted, TESTVECTOR_PLAINTEXT);

        println!("const TESTVECTOR_CIPHERTEXT: &[u8] = &{ciphertext:?};");
    }

    /// Locks in the serialized format of the type 0 ciphertext; must never break, or existing
    /// data will no longer decrypt.
    #[test]
    fn test_decrypt_testvector() {
        let decrypted =
            Aes256Cbc::decrypt(&TESTVECTOR_IV, TESTVECTOR_CIPHERTEXT, &TESTVECTOR_KEY).unwrap();

        assert_eq!(decrypted, TESTVECTOR_PLAINTEXT);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"EncryptMe!";

        let encrypted = Aes256Cbc::encrypt(&TESTVECTOR_IV, plaintext, &TESTVECTOR_KEY);
        let decrypted = Aes256Cbc::decrypt(&TESTVECTOR_IV, &encrypted, &TESTVECTOR_KEY).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_aes256() {
        let data: B64 = ("ByUF8vhyX4ddU9gcooznwA==").parse().unwrap();

        let decrypted =
            Aes256Cbc::decrypt(&TESTVECTOR_IV, data.as_bytes(), &TESTVECTOR_KEY).unwrap();

        assert_eq!(String::from_utf8(decrypted).unwrap(), "EncryptMe!");
    }

    #[test]
    fn test_decrypt_aes256_fails_on_invalid_padding() {
        let iv = [0u8; IV_SIZE];

        // Random block that will not decrypt to valid PKCS7 padding under this key/IV.
        let result = Aes256Cbc::decrypt(&iv, &[0u8; 16], &TESTVECTOR_KEY);
        assert_eq!(result, Err(SymmetricEncryptionError::FormatWrong));
    }
}

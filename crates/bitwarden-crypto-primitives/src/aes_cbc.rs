//! AES-256-CBC.
//!
//! Unauthenticated: always pair with a MAC (encrypt-then-MAC).

use crate::{Error, backend};

/// Key length in bytes.
pub const KEY_LEN: usize = 32;
/// IV length in bytes.
pub const IV_LEN: usize = 16;
/// Block length in bytes.
pub const BLOCK_LEN: usize = 16;

/// Encrypts `plaintext` with PKCS#7 padding.
pub fn encrypt(key: &[u8; KEY_LEN], iv: &[u8; IV_LEN], plaintext: &[u8]) -> Vec<u8> {
    backend::aes_cbc::encrypt(key, iv, plaintext)
}

/// Decrypts `ciphertext` and strips PKCS#7 padding.
pub fn decrypt(
    key: &[u8; KEY_LEN],
    iv: &[u8; IV_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    backend::aes_cbc::decrypt(key, iv, ciphertext)
}

/// Unpadded, block-at-a-time CBC encryption for streaming. Padding is the caller's job.
pub struct Encryptor(backend::aes_cbc::Encryptor);

impl Encryptor {
    /// Starts a CBC chain.
    pub fn new(key: &[u8; KEY_LEN], iv: &[u8; IV_LEN]) -> Self {
        Self(backend::aes_cbc::Encryptor::new(key, iv))
    }

    /// Encrypts the next block in place.
    pub fn encrypt_block(&mut self, block: &mut [u8; BLOCK_LEN]) {
        self.0.encrypt_block(block);
    }
}

/// Unpadded, block-at-a-time CBC decryption for streaming. Unpadding is the caller's job.
pub struct Decryptor(backend::aes_cbc::Decryptor);

impl Decryptor {
    /// Starts a CBC chain.
    pub fn new(key: &[u8; KEY_LEN], iv: &[u8; IV_LEN]) -> Self {
        Self(backend::aes_cbc::Decryptor::new(key, iv))
    }

    /// Decrypts the next block in place.
    pub fn decrypt_block(&mut self, block: &mut [u8; BLOCK_LEN]) {
        self.0.decrypt_block(block);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // NIST SP 800-38A F.2.5 (CBC-AES256.Encrypt), first two blocks.
    const KEY: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    const IV: &str = "000102030405060708090a0b0c0d0e0f";
    const PT: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51";
    const CT: &str = "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d";

    fn arr<const N: usize>(h: &str) -> [u8; N] {
        hex::decode(h).expect("hex").try_into().expect("length")
    }

    #[test]
    fn streaming_known_answer() {
        let (key, iv) = (arr::<KEY_LEN>(KEY), arr::<IV_LEN>(IV));
        let pt = hex::decode(PT).expect("hex");

        let mut enc = Encryptor::new(&key, &iv);
        let mut out = Vec::new();
        for chunk in pt.chunks_exact(BLOCK_LEN) {
            let mut block: [u8; BLOCK_LEN] = chunk.try_into().expect("block");
            enc.encrypt_block(&mut block);
            out.extend_from_slice(&block);
        }
        assert_eq!(hex::encode(&out), CT);

        let mut dec = Decryptor::new(&key, &iv);
        let mut back = Vec::new();
        for chunk in out.chunks_exact(BLOCK_LEN) {
            let mut block: [u8; BLOCK_LEN] = chunk.try_into().expect("block");
            dec.decrypt_block(&mut block);
            back.extend_from_slice(&block);
        }
        assert_eq!(back, pt);
    }

    #[test]
    fn padded_roundtrip_matches_streaming() {
        let (key, iv) = (arr::<KEY_LEN>(KEY), arr::<IV_LEN>(IV));
        let pt = hex::decode(PT).expect("hex");

        let ct = encrypt(&key, &iv, &pt);
        // Two data blocks plus one full padding block.
        assert_eq!(ct.len(), 3 * BLOCK_LEN);
        assert_eq!(hex::encode(&ct[..2 * BLOCK_LEN]), CT);
        assert_eq!(decrypt(&key, &iv, &ct), Ok(pt));
    }

    #[test]
    fn rejects_bad_length() {
        let (key, iv) = (arr::<KEY_LEN>(KEY), arr::<IV_LEN>(IV));
        assert_eq!(decrypt(&key, &iv, &[0u8; 15]), Err(Error::DecryptionFailed));
    }
}

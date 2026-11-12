use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};

use crate::Error;

type CbcEnc = cbc::Encryptor<aes::Aes256>;
type CbcDec = cbc::Decryptor<aes::Aes256>;

pub(crate) fn encrypt(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    CbcEnc::new(key.into(), iv.into()).encrypt_padded_vec::<Pkcs7>(plaintext)
}

pub(crate) fn decrypt(key: &[u8; 32], iv: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    CbcDec::new(key.into(), iv.into())
        .decrypt_padded_vec::<Pkcs7>(ciphertext)
        .map_err(|_| Error::DecryptionFailed)
}

/// Unpadded block-at-a-time CBC encryptor.
pub(crate) struct Encryptor(CbcEnc);

impl Encryptor {
    pub(crate) fn new(key: &[u8; 32], iv: &[u8; 16]) -> Self {
        Self(CbcEnc::new(key.into(), iv.into()))
    }

    pub(crate) fn encrypt_block(&mut self, block: &mut [u8; 16]) {
        self.0.encrypt_block(block.into());
    }
}

/// Unpadded block-at-a-time CBC decryptor.
pub(crate) struct Decryptor(CbcDec);

impl Decryptor {
    pub(crate) fn new(key: &[u8; 32], iv: &[u8; 16]) -> Self {
        Self(CbcDec::new(key.into(), iv.into()))
    }

    pub(crate) fn decrypt_block(&mut self, block: &mut [u8; 16]) {
        self.0.decrypt_block(block.into());
    }
}

use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};

use crate::{
    Error,
    aes_cbc::{BLOCK_LEN, IV_LEN, KEY_LEN},
};

type CbcEnc = cbc::Encryptor<aes::Aes256>;
type CbcDec = cbc::Decryptor<aes::Aes256>;

pub(crate) fn encrypt_pkcs7(key: &[u8; KEY_LEN], iv: &[u8; IV_LEN], plaintext: &[u8]) -> Vec<u8> {
    CbcEnc::new(key.into(), iv.into()).encrypt_padded_vec::<Pkcs7>(plaintext)
}

pub(crate) fn decrypt_pkcs7(
    key: &[u8; KEY_LEN],
    iv: &[u8; IV_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    CbcDec::new(key.into(), iv.into())
        .decrypt_padded_vec::<Pkcs7>(ciphertext)
        .map_err(|_| Error::DecryptionFailed)
}

/// Unpadded block-at-a-time CBC encryptor.
pub(crate) struct Encryptor(CbcEnc);

impl Encryptor {
    pub(crate) fn new(key: &[u8; KEY_LEN], iv: &[u8; IV_LEN]) -> Self {
        Self(CbcEnc::new(key.into(), iv.into()))
    }

    pub(crate) fn encrypt_block(&mut self, block: &mut [u8; BLOCK_LEN]) {
        self.0.encrypt_block(block.into());
    }
}

/// Unpadded block-at-a-time CBC decryptor.
pub(crate) struct Decryptor(CbcDec);

impl Decryptor {
    pub(crate) fn new(key: &[u8; KEY_LEN], iv: &[u8; IV_LEN]) -> Self {
        Self(CbcDec::new(key.into(), iv.into()))
    }

    pub(crate) fn decrypt_block(&mut self, block: &mut [u8; BLOCK_LEN]) {
        self.0.decrypt_block(block.into());
    }
}

use ::openssl::{cipher::Cipher, cipher_ctx::CipherCtx};
use zeroize::Zeroizing;

use crate::{
    Error,
    aes_cbc::{BLOCK_LEN, IV_LEN, KEY_LEN},
};

pub(crate) fn encrypt(key: &[u8; KEY_LEN], iv: &[u8; IV_LEN], plaintext: &[u8]) -> Vec<u8> {
    const INFALLIBLE: &str = "AES-CBC encryption of in-memory data does not fail";

    let mut ctx = CipherCtx::new().expect(INFALLIBLE);
    ctx.encrypt_init(Some(Cipher::aes_256_cbc()), Some(key), Some(iv))
        .expect(INFALLIBLE);

    // PKCS#7 always adds 1..=16 bytes.
    let mut out = Vec::with_capacity(plaintext.len() + BLOCK_LEN);
    ctx.cipher_update_vec(plaintext, &mut out)
        .expect(INFALLIBLE);
    ctx.cipher_final_vec(&mut out).expect(INFALLIBLE);
    out
}

pub(crate) fn decrypt(
    key: &[u8; KEY_LEN],
    iv: &[u8; IV_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut ctx = CipherCtx::new().map_err(|_| Error::DecryptionFailed)?;
    ctx.decrypt_init(Some(Cipher::aes_256_cbc()), Some(key), Some(iv))
        .map_err(|_| Error::DecryptionFailed)?;

    // Wipe partial plaintext if the padding does not verify.
    let mut out = Zeroizing::new(Vec::with_capacity(ciphertext.len() + BLOCK_LEN));
    ctx.cipher_update_vec(ciphertext, &mut out)
        .map_err(|_| Error::DecryptionFailed)?;
    ctx.cipher_final_vec(&mut out)
        .map_err(|_| Error::DecryptionFailed)?;

    Ok(std::mem::take(&mut *out))
}

/// Unpadded block-at-a-time CBC encryptor.
pub(crate) struct Encryptor(CipherCtx);

impl Encryptor {
    pub(crate) fn new(key: &[u8; KEY_LEN], iv: &[u8; IV_LEN]) -> Self {
        Self(unpadded_ctx(Direction::Encrypt, key, iv))
    }

    pub(crate) fn encrypt_block(&mut self, block: &mut [u8; BLOCK_LEN]) {
        process_block(&mut self.0, block);
    }
}

/// Unpadded block-at-a-time CBC decryptor.
pub(crate) struct Decryptor(CipherCtx);

impl Decryptor {
    pub(crate) fn new(key: &[u8; KEY_LEN], iv: &[u8; IV_LEN]) -> Self {
        Self(unpadded_ctx(Direction::Decrypt, key, iv))
    }

    pub(crate) fn decrypt_block(&mut self, block: &mut [u8; BLOCK_LEN]) {
        process_block(&mut self.0, block);
    }
}

#[derive(Clone, Copy)]
enum Direction {
    Encrypt,
    Decrypt,
}

/// CBC context with padding off, so every update emits exactly the blocks it was given.
fn unpadded_ctx(direction: Direction, key: &[u8; KEY_LEN], iv: &[u8; IV_LEN]) -> CipherCtx {
    const INFALLIBLE: &str = "AES-CBC setup with fixed-size key and IV does not fail";

    let mut ctx = CipherCtx::new().expect(INFALLIBLE);
    let cipher = Some(Cipher::aes_256_cbc());
    match direction {
        Direction::Encrypt => ctx.encrypt_init(cipher, Some(key), Some(iv)),
        Direction::Decrypt => ctx.decrypt_init(cipher, Some(key), Some(iv)),
    }
    .expect(INFALLIBLE);
    ctx.set_padding(false);
    ctx
}

/// Runs one block through the chain in place.
fn process_block(ctx: &mut CipherCtx, block: &mut [u8; BLOCK_LEN]) {
    // `cipher_update` wants room for one extra block; the scratch may hold plaintext.
    let mut scratch = Zeroizing::new([0u8; 2 * BLOCK_LEN]);
    let written = ctx
        .cipher_update(block.as_slice(), Some(scratch.as_mut_slice()))
        .expect("unpadded CBC accepts whole blocks");
    debug_assert_eq!(written, BLOCK_LEN);
    block.copy_from_slice(&scratch[..BLOCK_LEN]);
}

use ::openssl::{cipher::Cipher, cipher_ctx::CipherCtx};
use zeroize::Zeroizing;

use crate::{
    Error,
    aes_gcm::{KEY_LEN, NONCE_LEN, TAG_LEN},
};

pub(crate) fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    const INFALLIBLE: &str = "AES-GCM encryption of in-memory data does not fail";

    let mut ctx = CipherCtx::new().expect(INFALLIBLE);
    ctx.encrypt_init(Some(Cipher::aes_256_gcm()), Some(key), Some(nonce))
        .expect(INFALLIBLE);
    ctx.cipher_update(aad, None).expect(INFALLIBLE);

    // GCM is a stream mode: ciphertext and plaintext have the same length.
    let mut out = vec![0u8; plaintext.len() + TAG_LEN];
    let (ct, tag) = out.split_at_mut(plaintext.len());
    ctx.cipher_update(plaintext, Some(ct)).expect(INFALLIBLE);
    ctx.cipher_final(&mut []).expect(INFALLIBLE);
    ctx.tag(tag).expect(INFALLIBLE);
    out
}

pub(crate) fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    let Some(ct_len) = ciphertext.len().checked_sub(TAG_LEN) else {
        return Err(Error::DecryptionFailed);
    };
    let (ct, tag) = ciphertext.split_at(ct_len);

    let mut ctx = CipherCtx::new().map_err(|_| Error::DecryptionFailed)?;
    ctx.decrypt_init(Some(Cipher::aes_256_gcm()), Some(key), Some(nonce))
        .map_err(|_| Error::DecryptionFailed)?;
    ctx.set_tag(tag).map_err(|_| Error::DecryptionFailed)?;
    ctx.cipher_update(aad, None)
        .map_err(|_| Error::DecryptionFailed)?;

    // OpenSSL writes plaintext before checking the tag; wipe it if the tag does not verify.
    let mut out = Zeroizing::new(vec![0u8; ct_len]);
    ctx.cipher_update(ct, Some(&mut out))
        .map_err(|_| Error::DecryptionFailed)?;
    ctx.cipher_final(&mut [])
        .map_err(|_| Error::DecryptionFailed)?;

    Ok(std::mem::take(&mut *out))
}

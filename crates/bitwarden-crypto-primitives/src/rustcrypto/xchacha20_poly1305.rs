use chacha20poly1305::{KeyInit, XChaCha20Poly1305, aead::AeadInOut};

use crate::{
    Error,
    xchacha20_poly1305::{KEY_LEN, NONCE_LEN},
};

pub(crate) fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let mut buffer = plaintext.to_vec();
    XChaCha20Poly1305::new(key.into())
        .encrypt_in_place(nonce.into(), aad, &mut buffer)
        .expect("XChaCha20-Poly1305 encryption of in-memory data does not fail");
    buffer
}

pub(crate) fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut buffer = ciphertext.to_vec();
    XChaCha20Poly1305::new(key.into())
        .decrypt_in_place(nonce.into(), aad, &mut buffer)
        .map_err(|_| Error::DecryptionFailed)?;
    Ok(buffer)
}

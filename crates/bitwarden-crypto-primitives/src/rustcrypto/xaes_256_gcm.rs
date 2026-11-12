use xaes_256_gcm::{
    Xaes256Gcm,
    aead::{AeadInOut, KeyInit},
};

use crate::Error;

pub(crate) fn encrypt(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut buffer = plaintext.to_vec();
    Xaes256Gcm::new(key.into())
        .encrypt_in_place(nonce.into(), aad, &mut buffer)
        .expect("XAES-256-GCM encryption of in-memory data does not fail");
    buffer
}

pub(crate) fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut buffer = ciphertext.to_vec();
    Xaes256Gcm::new(key.into())
        .decrypt_in_place(nonce.into(), aad, &mut buffer)
        .map_err(|_| Error::DecryptionFailed)?;
    Ok(buffer)
}

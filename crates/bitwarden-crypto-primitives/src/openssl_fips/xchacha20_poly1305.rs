//! Unsupported: OpenSSL has no HChaCha20, which XChaCha20 needs.

use crate::{
    Error,
    xchacha20_poly1305::{KEY_LEN, NONCE_LEN},
};

const UNSUPPORTED: &str = "XChaCha20-Poly1305 is not available on the OpenSSL backend";

pub(crate) fn encrypt(
    _key: &[u8; KEY_LEN],
    _nonce: &[u8; NONCE_LEN],
    _aad: &[u8],
    _plaintext: &[u8],
) -> Vec<u8> {
    unimplemented!("{UNSUPPORTED}")
}

pub(crate) fn decrypt(
    _key: &[u8; KEY_LEN],
    _nonce: &[u8; NONCE_LEN],
    _aad: &[u8],
    _ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    unimplemented!("{UNSUPPORTED}")
}

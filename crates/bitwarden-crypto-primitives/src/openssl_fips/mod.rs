//! OpenSSL (>= 3.5) backend driver. Each submodule mirrors one public module of the crate.
//!
//! OpenSSL has no HChaCha20 (needed for XChaCha20) and no ristretto255 group API, so those two
//! modules are unsupported and panic.

pub(crate) mod aes_cbc;
pub(crate) mod aes_gcm;
pub(crate) mod argon2;
pub(crate) mod digest;
pub(crate) mod ed25519;
pub(crate) mod hkdf;
pub(crate) mod hmac;
pub(crate) mod ml_dsa_44;
pub(crate) mod p256;
pub(crate) mod pbkdf2;
pub(crate) mod random;
pub(crate) mod ristretto255;
pub(crate) mod rsa;
pub(crate) mod xaes_256_gcm;
pub(crate) mod xchacha20_poly1305;

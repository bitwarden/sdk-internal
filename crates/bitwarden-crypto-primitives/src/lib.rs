#![doc = include_str!("../README.md")]

// Backend driver. Every public module is a thin wrapper over the matching `backend` module, so
// callers never see backend types.
//
//   caller ──► bitwarden_crypto_primitives::<module> ──► backend::<module> ──► RustCrypto
mod rustcrypto;
use rustcrypto as backend;

mod error;
pub use error::Error;

pub mod aes_cbc;
pub mod aes_gcm;
pub mod argon2;
pub mod ed25519;
pub mod hkdf;
pub mod hmac;
pub mod ml_dsa;
pub mod p256;
pub mod pbkdf2;
pub mod random;
pub mod ristretto255;
pub mod rsa;
pub mod sha1;
pub mod sha256;
pub mod sha384;
pub mod sha512;
pub mod tuple_hash;
pub mod xaes_256_gcm;
pub mod xchacha20_poly1305;

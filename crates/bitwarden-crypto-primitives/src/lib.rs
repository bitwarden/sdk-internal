#![doc = include_str!("../README.md")]

// Backend driver, chosen at compile time with the `bitwarden_crypto_backend` cfg (see README).
// Every public module is a thin wrapper over the matching `backend` module, so callers never see
// backend types.
//
//   caller ──► bitwarden_crypto_primitives::<module> ──► backend::<module> ─┬─► RustCrypto (default)
//                                                                          └─► OpenSSL (>= 3.5)
//
// The OpenSSL driver re-exports the RustCrypto `xchacha20_poly1305` and `ristretto255` modules,
// which OpenSSL cannot provide, so `rustcrypto` is always compiled. On the OpenSSL backend its
// remaining modules only serve the cross-backend tests.
#[cfg(all(bitwarden_crypto_backend = "openssl", target_arch = "wasm32"))]
compile_error!("The `openssl` crypto backend is not available on wasm32.");

#[cfg_attr(bitwarden_crypto_backend = "openssl", allow(dead_code))]
mod rustcrypto;
#[cfg(not(bitwarden_crypto_backend = "openssl"))]
use rustcrypto as backend;

#[cfg(bitwarden_crypto_backend = "openssl")]
mod openssl;
#[cfg(bitwarden_crypto_backend = "openssl")]
use self::openssl as backend;

#[cfg(all(test, bitwarden_crypto_backend = "openssl"))]
mod cross_backend_tests;

mod error;
#[cfg(test)]
mod test_vectors;
pub use error::Error;

#[macro_use]
mod hash_module;

pub mod aes_cbc;
pub mod aes_gcm;
pub mod argon2;
pub mod ed25519;
pub mod hkdf;
pub mod hmac;
pub mod ml_dsa_44;
pub mod p256;
pub mod pbkdf2;
pub mod random;
pub mod ristretto255;
pub mod rsa;
pub mod sha1;
pub mod sha256;
pub mod sha384;
pub mod sha512;
pub mod xaes_256_gcm;
pub mod xchacha20_poly1305;

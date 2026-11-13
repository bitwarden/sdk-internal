//! Keeper "direct" importer cryptography.
//!
//! This is a byte-for-byte port of the Keeper access layer's `crypto.ts`. It implements
//! **Keeper's** wire formats, not Bitwarden's, so it deliberately does **not** live in
//! `bitwarden-crypto`: the formats are unauthenticated AES-CBC ("aes-v1"), AES-GCM with a prepended
//! nonce ("aes-v2"), RSA PKCS#1 v1.5 (unsupported), an ECDH-P256 → SHA-256 → AES-GCM scheme, and
//! Keeper's custom `encryptionParams` blob. The primitives come from `bitwarden_crypto_primitives`.
//!
//! Every function here must stay compatible with data produced by Keeper's clients; do not change
//! the formats.

#![allow(dead_code)] // Ported ahead of the Keeper access layer that will consume it; see PM-38816.

use bitwarden_crypto_primitives::{
    aes_cbc, aes_gcm,
    p256::{PublicKey, SecretKey},
    pbkdf2::pbkdf2_hmac_sha256,
    sha256,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

mod error;
pub(crate) use error::*;
mod types;
mod utils;

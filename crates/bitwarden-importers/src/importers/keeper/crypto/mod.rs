//! Keeper "direct" importer cryptography.
//!
//! This is a byte-for-byte port of the Keeper access layer's `crypto.ts`. It implements
//! **Keeper's** wire formats, not Bitwarden's, so it deliberately does **not** live in
//! `bitwarden-crypto`: the formats are unauthenticated AES-CBC ("aes-v1"), AES-GCM with a prepended
//! nonce ("aes-v2"), RSA PKCS#1 v1.5 (unsupported), an ECDH-P256 → SHA-256 → AES-GCM scheme, and
//! Keeper's custom `encryptionParams` blob. Where a primitive is standard we reuse
//! `bitwarden_crypto` (`pbkdf2`) and otherwise use the RustCrypto crates directly.
//!
//! Every function here must stay compatible with data produced by Keeper's clients; do not change
//! the formats.

#![allow(dead_code)] // Ported ahead of the Keeper access layer that will consume it; see PM-38816.

use aes::cipher::{
    BlockModeDecrypt, KeyIvInit,
    block_padding::{NoPadding, Pkcs7},
};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use p256::{
    PublicKey, SecretKey,
    elliptic_curve::{Generate, sec1::ToSec1Point},
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};
use pbkdf2::pbkdf2_hmac_array;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

mod error;
pub(crate) use error::*;
mod types;
mod utils;

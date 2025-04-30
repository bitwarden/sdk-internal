//! Mobile specific functionality.
//!
//! This module consists of stop-gap functionality for the mobile clients until the SDK owns it's
//! own state.

pub mod crypto;
mod kdf;

mod client_kdf;
mod crypto_client;

pub use client_kdf::ClientKdf;
pub use crypto_client::CryptoClient;

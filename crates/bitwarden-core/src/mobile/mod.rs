//! Mobile specific functionality.
//!
//! This module consists of stop-gap functionality for the mobile clients until the SDK owns it's
//! own state.

mod kdf;

mod client_kdf;

pub use client_kdf::KdfClient;

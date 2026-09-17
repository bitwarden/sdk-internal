//! # Bitwarden Autotype
//!
//! This crate provides encrypted IPC channels for the Bitwarden Desktop Autotype GA implementation,
//! using [`bitwarden_ipc`] within sdk-internal.

pub mod echo;

/// Wasm support module for autotype.
#[cfg(feature = "wasm")]
pub mod wasm;

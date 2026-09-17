#![doc = include_str!("../README.md")]

pub mod echo;

/// Wasm support module for autotype.
#[cfg(feature = "wasm")]
pub mod wasm;

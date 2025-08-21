#![doc = include_str!("../README.md")]

mod b64;
mod b64url;

pub use b64::B64;
pub use b64url::B64Url;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

#[cfg(feature = "uniffi")]
mod uniffi_support;

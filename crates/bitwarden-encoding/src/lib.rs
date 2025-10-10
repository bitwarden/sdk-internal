#![doc = include_str!("../README.md")]

mod b64;
mod b64url;
mod serde;

pub use b64::{B64, NotB64EncodedError};
pub use b64url::{B64Url, NotB64UrlEncodedError};
pub use serde::FromStrVisitor;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

#[cfg(feature = "uniffi")]
mod uniffi_support;

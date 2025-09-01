#![doc = include_str!("../README.md")]

mod b64;
mod b64url;
mod serde;

pub use b64::{NotB64Encoded, B64};
pub use b64url::{B64Url, NotB64UrlEncoded};
pub use serde::FromStrVisitor;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

#[cfg(feature = "uniffi")]
mod uniffi_support;

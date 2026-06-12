#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

mod sensitive;
mod sensitive_slice;
mod sensitive_string;

pub use sensitive::{ExposeSensitive, Sensitive};
pub use sensitive_slice::SensitiveSlice;
pub use sensitive_string::SensitiveString;

#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

#[cfg(feature = "uniffi")]
mod uniffi_support;

mod configuration;
mod error;
mod util;

pub use configuration::Configuration;
pub use error::Error;
pub use util::{AuthRequired, ContentType, parse_deep_object, urlencode};

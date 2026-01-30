#![doc = include_str!("../README.md")]

// Enable uniffi scaffolding when the "uniffi" feature is enabled.
#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

mod client;
pub use client::{UserCryptoManagementClient, UserCryptoManagementClientExt};

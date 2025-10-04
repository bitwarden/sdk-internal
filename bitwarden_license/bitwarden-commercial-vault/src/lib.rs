#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
mod uniffi_support;

mod vault_client;
pub use vault_client::{CommercialVaultClient, CommercialVaultClientExt};

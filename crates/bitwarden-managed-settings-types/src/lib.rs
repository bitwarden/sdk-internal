#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

mod profile;

pub use profile::{ManagedSettingsError, ManagementProfile};

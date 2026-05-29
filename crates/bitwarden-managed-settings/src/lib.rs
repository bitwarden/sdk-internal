#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
mod uniffi_support;

mod managed_settings_client;
mod override_trait;
mod profile;
mod store;

pub use managed_settings_client::{ManagedSettingsClient, ManagedSettingsClientExt};
pub use override_trait::ApplyManagedOverride;
pub use profile::{ManagementProfile, ManagementSource, ManagedSettingsError};

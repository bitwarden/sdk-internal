#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
mod uniffi_support;

mod catalog;
mod managed_settings_client;
mod override_trait;

pub use bitwarden_managed_settings_types::{ManagedSettingsError, ManagementProfile};
pub use catalog::{managed_keys, ManagedKey};
pub use managed_settings_client::{
    ManagedSettingsBuilderExt, ManagedSettingsClient, ManagedSettingsClientExt,
};
pub use override_trait::ApplyManagedOverride;

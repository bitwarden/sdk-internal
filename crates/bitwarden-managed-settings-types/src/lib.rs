#![doc = "Shared, dependency-light types for the managed-settings framework."]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

mod profile;

pub use profile::{ManagedSettingsError, ManagementProfile};

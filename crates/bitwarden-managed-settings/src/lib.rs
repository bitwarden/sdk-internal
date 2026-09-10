#![doc = include_str!("../README.md")]

mod managed_settings_client;
pub use bitwarden_managed_settings_types::ManagementProfile;
pub use managed_settings_client::{ManagedSettingsClient, ManagedSettingsClientExt};

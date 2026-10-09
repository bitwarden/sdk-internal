#![doc = include_str!("../README.md")]

mod managed_settings_client;
#[cfg(feature = "wasm")]
mod mirror;
mod normalize;
pub use bitwarden_managed_settings_types::{ManagedSettingsError, ManagementProfile};
pub use managed_settings_client::{ManagedSettingsClient, ManagedSettingsClientExt};

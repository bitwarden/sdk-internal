#![doc = include_str!("../README.md")]

// Enable uniffi scaffolding when the "uniffi" feature is enabled.
#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

mod key_connector_migration;
mod key_rotation;
mod pin_settings;
mod user_crypto_management_client;
pub use pin_settings::{PinLockType, PinSettingsClient, PinSettingsError};
pub use user_crypto_management_client::{
    UserCryptoManagementClient, UserCryptoManagementClientExt,
};

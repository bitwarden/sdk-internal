#![doc = include_str!("../README.md")]

// Enable uniffi scaffolding when the "uniffi" feature is enabled.
#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

mod key_connector_migration;
mod key_rotation;
mod user_crypto_management_client;
mod pin_settings;
pub use pin_settings::PinSettingsClient;
pub use user_crypto_management_client::{
    UserCryptoManagementClient, UserCryptoManagementClientExt,
};

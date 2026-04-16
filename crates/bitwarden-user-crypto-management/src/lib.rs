#![doc = include_str!("../README.md")]

// Enable uniffi scaffolding when the "uniffi" feature is enabled.
#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

mod key_connector_migration;
mod key_rotation;
mod user_crypto_management_client;
pub use user_crypto_management_client::{
    UserCryptoManagementClient, UserCryptoManagementClientExt,
};
mod example_method;
mod key_connector_client;
pub use key_connector_client::{KeyConnectorClient, KeyConnectorClientExt};

#![doc = include_str!("../README.md")]

// Enable uniffi scaffolding when the "uniffi" feature is enabled.
#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

mod change_kdf;
mod key_connector_migration;
mod key_id_backfill;
mod key_rotation;
mod pin_settings;
mod public_key_encryption_key_pair_regeneration;
mod user_crypto_management_client;
mod v2_migration_permission;
pub use change_kdf::ChangeKdfError;
pub use key_id_backfill::KeyIdBackfillError;
pub use pin_settings::PinSettingsClient;
pub use user_crypto_management_client::{
    UserCryptoManagementClient, UserCryptoManagementClientExt,
};
pub use v2_migration_permission::MigrationPermission;

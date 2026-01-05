#![doc = include_str!("../README.md")]

mod key;
mod repository;
mod setting;

use bitwarden_state::repository::RepositoryMigrationStep;
pub use key::Key;
pub use repository::{ClientSettingsExt, SettingsRepository};
pub use setting::Setting;

/// Get the migration step for the Setting repository item.
///
/// This should be included in the application's migration list when initializing
/// the database to ensure the settings table is created.
pub fn get_settings_migration_step() -> RepositoryMigrationStep {
    Setting::migration_step()
}

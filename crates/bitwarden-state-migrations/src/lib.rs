#![doc = include_str!("../README.md")]

use bitwarden_state::repository::{RepositoryItem, RepositoryMigrationStep, RepositoryMigrations};
use bitwarden_vault::{Cipher, Folder};

/// Returns a list of all SDK-managed repository migrations.
pub fn get_sdk_managed_migrations() -> RepositoryMigrations {
    use RepositoryMigrationStep::*;
    RepositoryMigrations::new(vec![
        // Add any new migrations here. Note that order matters, and that removing a repository
        // requires a separate migration step using `Remove(...)`.
        Add(Cipher::data()),
        Add(Folder::data()),
    ])
}

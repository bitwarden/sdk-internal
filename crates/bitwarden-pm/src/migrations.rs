//! Manages repository migrations for the Bitwarden SDK.

use bitwarden_core::key_management::UserKeyState;
use bitwarden_state::{
    SettingItem,
    repository::{RepositoryItem, RepositoryMigrationStep, RepositoryMigrations},
};
use bitwarden_vault::{Cipher, Folder};

/// Returns a list of all SDK-managed repository migrations.
pub fn get_sdk_managed_migrations() -> RepositoryMigrations {
    use RepositoryMigrationStep::*;
    RepositoryMigrations::new(vec![
        // Add any new migrations here. Note that order matters, and that removing a repository
        // requires a separate migration step using `Remove(...)`.
        Add(Cipher::data()),
        Add(Folder::data()),
        Add(UserKeyState::data()),
        Add(SettingItem::data()),
    ])
}

/// Macro to create the client managed repositories for the SDK.
/// To add a new repository, add it to the list in the macro invocation.
/// This is meant to be used by the final application crates (e.g., bitwarden-uniffi,
/// bitwarden-wasm-internal, bw).
#[macro_export]
macro_rules! create_client_managed_repositories {
    ($container_name:ident, $macro:ident) => {
        $macro! {
            $container_name;
            // List any SDK-managed repositories here. The format is:
            // <fully qualified path to the item>, <item type idenfier>, <field name>, <name of the repository implementation>
            ::bitwarden_vault::Cipher, Cipher, cipher, CipherRepository;
            ::bitwarden_vault::Folder, Folder, folder, FolderRepository;
            ::bitwarden_core::key_management::UserKeyState, UserKeyState, user_key_state, UserKeyStateRepository;
        }
    };
}

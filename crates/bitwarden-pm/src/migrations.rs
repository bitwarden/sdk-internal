//! Manages repository migrations for the Bitwarden SDK.

use bitwarden_core::client::persisted_state::OrganizationSharedKey;
use bitwarden_organizations::ProfileOrganization;
use bitwarden_policies::Policy;
use bitwarden_send::Send;
use bitwarden_state::{
    PersistedValueItem,
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
        Add(PersistedValueItem::data()),
        Add(OrganizationSharedKey::data()),
        Add(Send::data()),
        Add(Policy::data()),
        Add(ProfileOrganization::data()),
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
            ::bitwarden_core::key_management::LocalUserDataKeyState, LocalUserDataKeyState, local_user_data_key_state, LocalUserDataKeyStateRepository;
            ::bitwarden_core::client::persisted_state::OrganizationSharedKey, OrganizationSharedKey, organization_shared_key, OrganizationSharedKeyRepository;
            ::bitwarden_send::Send, Send, send, SendRepository;
            ::bitwarden_policies::Policy, Policy, policy, PolicyRepository;
            ::bitwarden_organizations::ProfileOrganization, ProfileOrganization, organization, ProfileOrganizationRepository;
        }
    };
}

/// Macro to create the client-managed persisted values for the SDK.
/// To let clients manage a persisted value, add its key to the list in the macro invocation. The
/// key must be declared with `register_persisted_value!`, and UniFFI must support its value type.
/// This is meant to be used by the final application crates (e.g., bitwarden-uniffi,
/// bitwarden-wasm-internal).
#[macro_export]
macro_rules! create_client_managed_values {
    ($container_name:ident, $macro:ident) => {
        $macro! {
            $container_name;
            // List any client-managed persisted values here. The format is:
            // <fully qualified path to the key>, <TypeScript value type>, <field name>, <name of the value implementation>
            ::bitwarden_sync::LAST_SYNC, "DateTime<Utc>", last_sync, LastSyncPersistedValue;
        }
    };
}

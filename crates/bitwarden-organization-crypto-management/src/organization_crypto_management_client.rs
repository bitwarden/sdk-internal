//! Client to manage the cryptographic state of the user's organizations.

use std::sync::Arc;

use bitwarden_core::{Client, FromClient, client::ApiConfigurations, key_management::KeySlotIds};
use bitwarden_crypto::KeyStore;
use bitwarden_organizations::ProfileOrganization;
use bitwarden_state::repository::Repository;

/// Client for managing the cryptographic state of the user's organizations.
#[bitwarden_ffi::wasm_object]
#[derive(FromClient)]
pub struct OrganizationCryptoManagementClient {
    pub(crate) key_store: KeyStore<KeySlotIds>,
    pub(crate) api_configurations: Arc<ApiConfigurations>,
    pub(crate) repository: Option<Arc<dyn Repository<ProfileOrganization>>>,
}

/// Extension trait to add the organization-crypto-management client to the main Bitwarden SDK
/// client.
pub trait OrganizationCryptoManagementClientExt {
    /// Get the organization-crypto-management client.
    fn organization_crypto_management(&self) -> OrganizationCryptoManagementClient;
}

impl OrganizationCryptoManagementClientExt for Client {
    fn organization_crypto_management(&self) -> OrganizationCryptoManagementClient {
        OrganizationCryptoManagementClient::from_client(self)
    }
}

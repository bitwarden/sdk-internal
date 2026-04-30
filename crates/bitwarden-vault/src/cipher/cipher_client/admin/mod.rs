use std::sync::Arc;

use bitwarden_core::{
    Client, FromClient,
    client::{ApiConfigurations, FromClientPart},
    key_management::KeySlotIds,
};
use bitwarden_crypto::KeyStore;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

mod create;
mod delete;
mod delete_attachment;
mod edit;
mod get;
mod restore;

pub use get::GetAssignedOrgCiphersAdminError;

/// Client for performing admin operations on ciphers. Unlike the regular CiphersClient,
/// this client uses the admin server API endpoints, and does not modify local state.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct CipherAdminClient {
    pub(crate) key_store: KeyStore<KeySlotIds>,
    pub(crate) api_configurations: Arc<ApiConfigurations>,
    #[deprecated(
        note = "Use the component fields (key_store, api_configurations) for new operations"
    )]
    pub(crate) client: Client,
}

impl FromClient for CipherAdminClient {
    fn from_client(client: &Client) -> Self {
        #[allow(deprecated)]
        Self {
            key_store: client.get_part(),
            api_configurations: client.get_part(),
            client: client.clone(),
        }
    }
}

#[allow(deprecated)]
impl CipherAdminClient {
    async fn is_strict_decrypt(&self) -> bool {
        self.client
            .internal
            .get_flags()
            .await
            .strict_cipher_decryption
    }
}

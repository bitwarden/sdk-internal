use bitwarden_core::Client;
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
    pub(crate) client: Client,
}

impl CipherAdminClient {
    async fn is_strict_decrypt(&self) -> bool {
        self.client
            .internal
            .get_flags()
            .await
            .strict_cipher_decryption
    }
}

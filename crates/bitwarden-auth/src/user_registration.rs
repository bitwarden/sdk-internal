//! Client for account registration and cryptography initialization related API methods.
//! It is used both for the initial registration request in the case of password registrations,
//! and for cryptography initialization for a jit provisioned user. After a method
//! on this client is called, the user account should have initialized account keys, an
//! authentication method such as SSO or master password, and a decryption method such as
//! key-connector, TDE, or master password.

use bitwarden_core::Client;
use bitwarden_encoding::B64;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Client for initializing a user account.
#[derive(Clone)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct UserRegistrationClient {
    #[allow(dead_code)]
    pub(crate) client: Client,
}

impl UserRegistrationClient {
    pub(crate) fn new(client: Client) -> Self {
        Self { client }
    }
}
#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl UserRegistrationClient {
    /// Example method to demonstrate usage of the client.
    /// Note: This will be removed once real methods are implemented.
    #[allow(unused)]
    async fn example(&self) {
        let client = &self.client.internal;
        #[allow(unused_variables)]
        let api_client = &client.get_api_configurations().await.api_client;
        // Do API request here. It will be authenticated using the client's tokens.
    }

    async fn post_keys_for_tde_registration(
        &self,
        user_id: String,
        org_public_key: B64,
        trust_device: bool,
    ) {
        let client = &self.client.internal;
        #[allow(unused_variables)]
        let api_client = &client.get_api_configurations().await.api_client;
        let user_id = client.get_user_id().expect("User ID not set");
        let (cryptography_state, device_key_set, admin_reset_key) = self
            .client
            .crypto()
            .make_user_tde_registration(user_id, org_public_key)
            .expect("Failed to make TDE registration");
        // Post the generated keys to the API here.
        let request = bitwarden_api_api::models::KeysRequestModel {
            
        }
    }
}

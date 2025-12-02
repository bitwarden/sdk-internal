//! Client for account registration and cryptography initialization related API methods.
//! It is used both for the initial registration request in the case of password registrations,
//! and for cryptography initialization for a jit provisioned user. After a method
//! on this client is called, the user account should have initialized account keys, an
//! authentication method such as SSO or master password, and a decryption method such as
//! key-connector, TDE, or master password.

use bitwarden_api_api::models::{
    DeviceRequestModel, OrganizationUserResetPasswordEnrollmentRequestModel,
};
use bitwarden_core::{Client, key_management::account_cryptographic_state};
use bitwarden_encoding::B64;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::api;

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

        // First call crypto API to get all keys
        let (
            cryptography_state,
            account_cryptographic_state_request,
            device_key_set,
            reset_password_key,
        ) = self
            .client
            .crypto()
            .make_user_tde_registration(user_id, org_public_key)
            .expect("Failed to make TDE registration");

        // Post the generated keys to the API here. The user now has keys and is "registered", but has no unlock method.
        let request = bitwarden_api_api::models::KeysRequestModel {
            account_keys: Some(Box::new(account_cryptographic_state_request)),
            public_key: account_cryptographic_state_request.public_key,
            encrypted_private_key: account_cryptographic_state_request.encrypted_private_key,
        };
        api_client
            .accounts_api()
            .post_keys(request)
            .await
            .expect("API call failed");

        // Next, enroll the user for reset password using the reset password key generated above.
        api_client
            .organization_users_api()
            .put_reset_password_enrollment(
                org_id,
                user_id,
                OrganizationUserResetPasswordEnrollmentRequestModel {
                    reset_password_key: Some(reset_password_key),
                    master_password_hash: None,
                },
            )
            .await
            .expect("API call failed");

        // Finally, if trust_device is true, call the trust device API here to set up device trust.
        if trust_device {
            api_client
                .devices_api()
                .post(Some(bitwarden_api_api::models::DeviceRequestModel {
                    r#type: bitwarden_api_api::models::DeviceType::Android,
                    name: "".to_string(),
                    identifier: "".to_string(),
                    push_token: None,
                }))
        }
    }
}

//! Client for account registration and cryptography initialization related API methods.
//! It is used both for the initial registration request in the case of password registrations,
//! and for cryptography initialization for a jit provisioned user. After a method
//! on this client is called, the user account should have initialized account keys, an
//! authentication method such as SSO or master password, and a decryption method such as
//! key-connector, TDE, or master password.

use bitwarden_api_api::models::SetKeyConnectorKeyRequestModel;
use bitwarden_core::{
    Client, OrganizationId, UserId,
    key_management::{
        AccountCryptographyMakeKeysError, KeyConnectorApiClient,
        account_cryptographic_state::WrappedAccountCryptographicState,
    },
};
use bitwarden_crypto::EncString;
use bitwarden_encoding::B64;
use bitwarden_error::bitwarden_error;
use thiserror::Error;
use tracing::{error, info};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Client for initializing a user account.
#[derive(Clone)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct RegistrationClient {
    #[allow(dead_code)]
    pub(crate) client: Client,
}

impl RegistrationClient {
    pub(crate) fn new(client: Client) -> Self {
        Self { client }
    }
}
#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl RegistrationClient {
    /// Example method to demonstrate usage of the client.
    /// Note: This will be removed once real methods are implemented.
    #[allow(unused)]
    async fn example(&self) {
        let client = &self.client.internal;
        #[allow(unused_variables)]
        let api_client = &client.get_api_configurations().await.api_client;
        // Do API request here. It will be authenticated using the client's tokens.
    }

    /// Initializes a new cryptographic state for a user and posts it to the server; enrolls the
    /// user to key connector unlock.
    pub async fn post_keys_for_key_connector_registration(
        &self,
        key_connector_url: String,
        org_id: OrganizationId,
        user_id: UserId,
    ) -> Result<KeyConnectorRegistrationResult, UserRegistrationError> {
        let client = &self.client.internal;
        let api_client = &client.get_api_configurations().await.api_client;
        let key_connector_api_client =
            KeyConnectorApiClient::new(client, key_connector_url.as_str());

        internal_post_keys_for_key_connector_registration(
            self,
            api_client,
            &key_connector_api_client,
            org_id,
            user_id,
        )
        .await
    }
}

async fn internal_post_keys_for_key_connector_registration(
    registration_client: &RegistrationClient,
    api_client: &bitwarden_api_api::apis::ApiClient,
    key_connector_api_client: &KeyConnectorApiClient,
    org_id: OrganizationId,
    user_id: UserId,
) -> Result<KeyConnectorRegistrationResult, UserRegistrationError> {
    // First call crypto API to get all keys
    info!("Initializing account cryptography");
    let registration_crypto_result = registration_client
        .client
        .crypto()
        .make_user_key_connector_registration(user_id)
        .map_err(UserRegistrationError::AccountCryptographyMakeKeys)?;

    info!("Posting key connector key to key connector server");
    key_connector_api_client
        .post_or_put_key_connector_key(&registration_crypto_result.key_connector_key)
        .await
        .map_err(|e| {
            error!("Failed to post key connector key to key connector server: {e:?}");
            UserRegistrationError::KeyConnectorApi
        })?;

    info!("Posting user account cryptographic state to server");
    let request = SetKeyConnectorKeyRequestModel {
        key_connector_key_wrapped_user_key: Some(
            registration_crypto_result
                .key_connector_key_wrapped_user_key
                .to_string(),
        ),
        account_keys: Some(Box::new(registration_crypto_result.account_keys_request)),
        ..SetKeyConnectorKeyRequestModel::new(org_id.to_string())
    };
    api_client
        .accounts_key_management_api()
        .post_set_key_connector_key(Some(request))
        .await
        .map_err(|e| {
            error!("Failed to post account cryptographic state to server: {e:?}");
            UserRegistrationError::Api
        })?;

    info!("User initialized!");
    // Note: This passing out of state and keys is temporary. Once SDK state management is more
    // mature, the account cryptographic state and keys should be set directly here.
    Ok(KeyConnectorRegistrationResult {
        account_cryptographic_state: registration_crypto_result.account_cryptographic_state,
        key_connector_key: registration_crypto_result.key_connector_key.to_base64(),
        key_connector_key_wrapped_user_key: registration_crypto_result
            .key_connector_key_wrapped_user_key,
        user_key: registration_crypto_result.user_key.to_encoded().into(),
    })
}

/// Result of Key Connector registration process.
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct KeyConnectorRegistrationResult {
    /// The account cryptographic state of the user.
    pub account_cryptographic_state: WrappedAccountCryptographicState,
    /// The key connector key used for unlocking.
    pub key_connector_key: B64,
    /// The encrypted user key, wrapped with the key connector key.
    pub key_connector_key_wrapped_user_key: EncString,
    /// The decrypted user key. This can be used to get the consuming client to an unlocked state.
    pub user_key: B64,
}

/// Errors that can occur during user registration.
#[derive(Debug, Error)]
#[bitwarden_error(flat)]
pub enum UserRegistrationError {
    /// Key Connector API call failed.
    #[error("Key Connector Api call failed")]
    KeyConnectorApi,
    /// API call failed.
    #[error("Api call failed")]
    Api,
    /// Account cryptography initialization failed.
    #[error(transparent)]
    AccountCryptographyMakeKeys(#[from] AccountCryptographyMakeKeysError),
}

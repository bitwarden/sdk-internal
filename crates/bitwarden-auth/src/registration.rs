//! Client for account registration and cryptography initialization related API methods.
//! It is used both for the initial registration request in the case of password registrations,
//! and for cryptography initialization for a jit provisioned user. After a method
//! on this client is called, the user account should have initialized account keys, an
//! authentication method such as SSO or master password, and a decryption method such as
//! key-connector, TDE, or master password.

use std::str::FromStr;

use bitwarden_api_api::models::SetKeyConnectorKeyRequestModel;
use bitwarden_core::{
    Client, UserId,
    key_management::{
        AccountCryptographyMakeKeysError, KeyConnectorApiError,
        account_cryptographic_state::WrappedAccountCryptographicState,
        key_connector_api_post_or_put_key_connector_key,
    },
};
use bitwarden_crypto::EncString;
use bitwarden_encoding::B64;
use bitwarden_error::bitwarden_error;
use serde_bytes::ByteBuf;
use thiserror::Error;
use tracing::info;
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
        org_id: String,
        user_id: String,
    ) -> Result<KeyConnectorRegistrationResult, UserRegistrationError> {
        let client = &self.client.internal;
        let api_client = &client.get_api_configurations().await.api_client;
        let user_id =
            UserId::from_str(user_id.as_str()).map_err(|_| UserRegistrationError::Serialization)?;

        // First call crypto API to get all keys
        info!("Initializing account cryptography");
        let (
            cryptography_state,
            wrapped_user_key,
            user_key,
            account_cryptographic_state_request,
            key_connector_key,
        ) = self
            .client
            .crypto()
            .make_user_key_connector_registration(user_id)
            .map_err(UserRegistrationError::AccountCryptographyMakeKeys)?;

        info!("Posting key connector key to key connector server");
        key_connector_api_post_or_put_key_connector_key(
            &self.client,
            key_connector_url.as_str(),
            &key_connector_key,
        )
        .await
        .map_err(UserRegistrationError::KeyConnectorApi)?;

        info!("Posting user account cryptographic state to server");
        let request = SetKeyConnectorKeyRequestModel {
            key_connector_key_wrapped_user_key: Some(wrapped_user_key.to_string()),
            account_keys: Some(Box::new(account_cryptographic_state_request)),
            ..SetKeyConnectorKeyRequestModel::new(org_id)
        };
        api_client
            .accounts_key_management_api()
            .post_set_key_connector_key(Some(request))
            .await
            .map_err(|e| UserRegistrationError::Api(e.into()))?;

        info!("User initialized!");
        // Note: This passing out of state and keys is temporary. Once SDK state management is more
        // mature, the account cryptographic state and keys should be set directly here.
        Ok(KeyConnectorRegistrationResult {
            account_cryptographic_state: cryptography_state,
            key_connector_key: key_connector_key.to_base64(),
            key_connector_key_wrapped_user_key: wrapped_user_key,
            user_key: user_key.to_encoded().to_vec().into(),
        })
    }
}

/// Result of Key Connector registration process.
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct KeyConnectorRegistrationResult {
    /// The account cryptographic state of the user.
    pub account_cryptographic_state: WrappedAccountCryptographicState,
    /// The key connector key used for unlocking.
    pub key_connector_key: B64,
    /// The encrypted user key, wrapped with the key connector key.
    pub key_connector_key_wrapped_user_key: EncString,
    /// The decrypted user key. This can be used to get the consuming client to an unlocked state.
    pub user_key: ByteBuf,
}

/// Errors that can occur during user registration.
#[derive(Debug, Error)]
#[bitwarden_error(flat)]
pub enum UserRegistrationError {
    /// Key Connector API call failed.
    #[error(transparent)]
    KeyConnectorApi(#[from] KeyConnectorApiError),
    /// API call failed.
    #[error(transparent)]
    Api(#[from] bitwarden_core::ApiError),
    /// Account cryptography initialization failed.
    #[error(transparent)]
    AccountCryptographyMakeKeys(#[from] AccountCryptographyMakeKeysError),
    /// Serialization or deserialization error
    #[error("Serialization error")]
    Serialization,
}

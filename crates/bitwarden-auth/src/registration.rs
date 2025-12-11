//! Client for account registration and cryptography initialization related API methods.
//! It is used both for the initial registration request in the case of password registrations,
//! and for cryptography initialization for a jit provisioned user. After a method
//! on this client is called, the user account should have initialized account keys, an
//! authentication method such as SSO or master password, and a decryption method such as
//! key-connector, TDE, or master password.

use std::str::FromStr;

use bitwarden_api_api::models::{
    DeviceKeysRequestModel, KeysRequestModel, OrganizationUserResetPasswordEnrollmentRequestModel,
};
use bitwarden_core::{
    Client, UserId, key_management::account_cryptographic_state::WrappedAccountCryptographicState,
};
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

    /// Initializes a new cryptographic state for a user and posts it to the server; enrolls in
    /// admin password reset and finally enrolls the user to TDE unlock.
    pub async fn post_keys_for_tde_registration(
        &self,
        org_id: String,
        org_public_key: B64,
        // Note: Ideally these would be set for the register client, however no such functionality
        // exists at the moment
        user_id: String,
        device_id: String,
        trust_device: bool,
    ) -> Result<TdeRegistrationResult, UserRegistrationError> {
        let client = &self.client.internal;
        #[allow(unused_variables)]
        let api_client = &client.get_api_configurations().await.api_client;
        let user_id =
            UserId::from_str(user_id.as_str()).map_err(|_| UserRegistrationError::Serialization)?;

        // First call crypto API to get all keys
        info!("Initializing account cryptography");
        let (
            cryptography_state,
            user_key,
            account_cryptographic_state_request,
            device_key_set,
            reset_password_key,
        ) = self
            .client
            .crypto()
            .make_user_tde_registration(user_id, org_public_key)
            .map_err(|_| UserRegistrationError::Crypto)?;

        // Post the generated keys to the API here. The user now has keys and is "registered", but
        // has no unlock method.
        let request = KeysRequestModel {
            account_keys: Some(Box::new(account_cryptographic_state_request.clone())),
            // Note: This property is deprecated and will be removed
            public_key: account_cryptographic_state_request
                .account_public_key
                .ok_or(UserRegistrationError::Crypto)?,
            // Note: This property is deprecated and will be removed
            encrypted_private_key: account_cryptographic_state_request
                .user_key_encrypted_account_private_key
                .ok_or(UserRegistrationError::Crypto)?,
        };
        info!("Posting user account cryptographic state to server");
        api_client
            .accounts_api()
            .post_keys(Some(request))
            .await
            .map_err(|_| UserRegistrationError::Api)?;

        // Next, enroll the user for reset password using the reset password key generated above.
        info!("Enrolling into admin account recovery");
        api_client
            .organization_users_api()
            .put_reset_password_enrollment(
                uuid::Uuid::parse_str(&org_id).map_err(|_| UserRegistrationError::Serialization)?,
                user_id.into(),
                Some(OrganizationUserResetPasswordEnrollmentRequestModel {
                    reset_password_key: Some(reset_password_key.to_string()),
                    master_password_hash: None,
                }),
            )
            .await
            .map_err(|_| UserRegistrationError::Api)?;

        if trust_device {
            // Next, enroll the user for TDE unlock
            info!("Enrolling into trusted device decryption");
            api_client
                .devices_api()
                .put_keys(
                    device_id.as_str(),
                    Some(DeviceKeysRequestModel::new(
                        device_key_set.protected_user_key.to_string(),
                        device_key_set.protected_device_private_key.to_string(),
                        device_key_set.protected_device_public_key.to_string(),
                    )),
                )
                .await
                .map_err(|_| UserRegistrationError::Api)?;
        }

        info!("User initialized!");
        // Note: This passing out of state and keys is temporary. Once SDK state management is more
        // mature, the account cryptographic state and keys should be set directly here.
        Ok(TdeRegistrationResult {
            account_cryptographic_state: cryptography_state,
            device_key: device_key_set.device_key.to_string(),
            user_key: user_key.to_encoded().to_vec().into(),
        })
    }
}

/// Result of TDE registration process.
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct TdeRegistrationResult {
    /// The account cryptographic state of the user
    pub account_cryptographic_state: WrappedAccountCryptographicState,
    /// The device key
    pub device_key: String,
    /// The decrypted user key. This can be used to get the consuming client to an unlocked state.
    pub user_key: ByteBuf,
}

/// Errors that can occur during user registration.
#[derive(Debug, Error)]
#[bitwarden_error(flat)]
pub enum UserRegistrationError {
    /// API call failed.
    #[error("Api call failed")]
    Api,
    /// Cryptography initialization failed.
    #[error("Cryptography initialization failed")]
    Crypto,
    /// Serialization or deserialization error
    #[error("Serialization error")]
    Serialization,
}

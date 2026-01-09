//! Client for account registration and cryptography initialization related API methods.
//! It is used both for the initial registration request in the case of password registrations,
//! and for cryptography initialization for a jit provisioned user. After a method
//! on this client is called, the user account should have initialized account keys, an
//! authentication method such as SSO or master password, and a decryption method such as
//! key-connector, TDE, or master password.

use bitwarden_api_api::models::{
    DeviceKeysRequestModel, KeysRequestModel, OrganizationUserResetPasswordEnrollmentRequestModel,
    SetInitialPasswordRequestModel, SetKeyConnectorKeyRequestModel,
};
use bitwarden_core::{
    Client, OrganizationId, UserId,
    key_management::{
        MasterPasswordUnlockData, account_cryptographic_state::WrappedAccountCryptographicState,
    },
};
use bitwarden_crypto::EncString;
use bitwarden_encoding::B64;
use bitwarden_error::bitwarden_error;
use thiserror::Error;
use tracing::{error, info};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Request parameters for TDE (Trusted Device Encryption) registration.
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct TdeRegistrationRequest {
    /// Organization ID to enroll in
    pub org_id: OrganizationId,
    /// Organization's public key for encrypting the reset password key. This should be verified by
    /// the client and not verifying may compromise the security of the user's account.
    pub org_public_key: B64,
    /// User ID for the account being initialized
    pub user_id: UserId,
    /// Device identifier for TDE enrollment
    pub device_identifier: String,
    /// Whether to trust this device for TDE
    pub trust_device: bool,
}

/// Request parameters for SSO JIT master password registration.
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct JitMasterPasswordRegistrationRequest {
    /// Organization ID to enroll in
    pub org_id: OrganizationId,
    /// Organization's public key for encrypting the reset password key. This should be verified by
    /// the client and not verifying may compromise the security of the user's account.
    pub org_public_key: B64,
    /// Organization SSO identifier
    pub organization_sso_identifier: String,
    /// User ID for the account being initialized
    pub user_id: UserId,
    /// Salt for master password hashing, usually email
    pub salt: String,
    /// Master password for the account
    pub master_password: String,
    /// Optional hint for the master password
    pub master_password_hint: Option<String>,
}

/// Client for initializing a user account.
#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
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

#[cfg_attr(feature = "uniffi", uniffi::export)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl RegistrationClient {
    /// Initializes a new cryptographic state for a user and posts it to the server; enrolls in
    /// admin password reset and finally enrolls the user to TDE unlock.
    pub async fn post_keys_for_tde_registration(
        &self,
        request: TdeRegistrationRequest,
    ) -> Result<TdeRegistrationResponse, RegistrationError> {
        let client = &self.client.internal;
        let api_client = &client.get_api_configurations().await.api_client;
        internal_post_keys_for_tde_registration(self, api_client, request).await
    }

    /// Initializes a new cryptographic state for a user and posts it to the server; enrolls the
    /// user to key connector unlock.
    pub async fn post_keys_for_key_connector_registration(
        &self,
        key_connector_url: String,
        sso_org_identifier: String,
        user_id: UserId,
    ) -> Result<KeyConnectorRegistrationResult, RegistrationError> {
        let client = &self.client.internal;
        let configuration = &client.get_api_configurations().await;
        let key_connector_client = client.get_key_connector_client(key_connector_url);

        internal_post_keys_for_key_connector_registration(
            self,
            &configuration.api_client,
            &key_connector_client,
            sso_org_identifier,
            user_id,
        )
        .await
    }

    /// Initializes a new cryptographic state for a user and posts it to the server;
    /// enrolls the user to master password unlock.
    pub async fn post_keys_for_jit_password_registration(
        &self,
        request: JitMasterPasswordRegistrationRequest,
    ) -> Result<JitMasterPasswordRegistrationResponse, RegistrationError> {
        let client = &self.client.internal;
        let api_client = &client.get_api_configurations().await.api_client;
        internal_post_keys_for_jit_password_registration(self, api_client, request).await
    }
}

async fn internal_post_keys_for_tde_registration(
    registration_client: &RegistrationClient,
    api_client: &bitwarden_api_api::apis::ApiClient,
    request: TdeRegistrationRequest,
) -> Result<TdeRegistrationResponse, RegistrationError> {
    // First call crypto API to get all keys
    info!("Initializing account cryptography");
    let tde_registration_crypto_result = registration_client
        .client
        .crypto()
        .make_user_tde_registration(request.user_id, request.org_public_key.clone())
        .map_err(|_| RegistrationError::Crypto)?;

    // Post the generated keys to the API here. The user now has keys and is "registered", but
    // has no unlock method.
    let keys_request = KeysRequestModel {
        account_keys: Some(Box::new(
            tde_registration_crypto_result.account_keys_request.clone(),
        )),
        // Note: This property is deprecated and will be removed
        public_key: tde_registration_crypto_result
            .account_keys_request
            .account_public_key
            .ok_or(RegistrationError::Crypto)?,
        // Note: This property is deprecated and will be removed
        encrypted_private_key: tde_registration_crypto_result
            .account_keys_request
            .user_key_encrypted_account_private_key
            .ok_or(RegistrationError::Crypto)?,
    };
    info!("Posting user account cryptographic state to server");
    api_client
        .accounts_api()
        .post_keys(Some(keys_request))
        .await
        .map_err(|e| {
            tracing::error!("Failed to post account keys: {e:?}");
            RegistrationError::Api
        })?;

    // Next, enroll the user for reset password using the reset password key generated above.
    info!("Enrolling into admin account recovery");
    api_client
        .organization_users_api()
        .put_reset_password_enrollment(
            request.org_id.into(),
            request.user_id.into(),
            Some(OrganizationUserResetPasswordEnrollmentRequestModel {
                reset_password_key: Some(
                    tde_registration_crypto_result
                        .reset_password_key
                        .to_string(),
                ),
                master_password_hash: None,
            }),
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to enroll for reset password: {e:?}");
            RegistrationError::Api
        })?;

    if request.trust_device {
        // Next, enroll the user for TDE unlock
        info!("Enrolling into trusted device decryption");
        api_client
            .devices_api()
            .put_keys(
                request.device_identifier.as_str(),
                Some(DeviceKeysRequestModel::new(
                    tde_registration_crypto_result
                        .trusted_device_keys
                        .protected_user_key
                        .to_string(),
                    tde_registration_crypto_result
                        .trusted_device_keys
                        .protected_device_private_key
                        .to_string(),
                    tde_registration_crypto_result
                        .trusted_device_keys
                        .protected_device_public_key
                        .to_string(),
                )),
            )
            .await
            .map_err(|e| {
                tracing::error!("Failed to enroll device for TDE: {e:?}");
                RegistrationError::Api
            })?;
    }

    info!("User initialized!");
    // Note: This passing out of state and keys is temporary. Once SDK state management is more
    // mature, the account cryptographic state and keys should be set directly here.
    Ok(TdeRegistrationResponse {
        account_cryptographic_state: tde_registration_crypto_result.account_cryptographic_state,
        device_key: tde_registration_crypto_result
            .trusted_device_keys
            .device_key,
        user_key: tde_registration_crypto_result
            .user_key
            .to_encoded()
            .to_vec()
            .into(),
    })
}

/// Result of TDE registration process.
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct TdeRegistrationResponse {
    /// The account cryptographic state of the user
    pub account_cryptographic_state: WrappedAccountCryptographicState,
    /// The device key
    pub device_key: B64,
    /// The decrypted user key. This can be used to get the consuming client to an unlocked state.
    pub user_key: B64,
}

async fn internal_post_keys_for_key_connector_registration(
    registration_client: &RegistrationClient,
    api_client: &bitwarden_api_api::apis::ApiClient,
    key_connector_api_client: &bitwarden_api_key_connector::apis::ApiClient,
    sso_org_identifier: String,
    user_id: UserId,
) -> Result<KeyConnectorRegistrationResult, RegistrationError> {
    // First call crypto API to get all keys
    info!("Initializing account cryptography");
    let registration_crypto_result = registration_client
        .client
        .crypto()
        .make_user_key_connector_registration(user_id)
        .map_err(|_| RegistrationError::Crypto)?;

    info!("Posting key connector key to key connector server");
    let key_connector_key: B64 = registration_crypto_result.key_connector_key.into();
    post_key_to_key_connector(key_connector_api_client, &key_connector_key).await?;

    info!("Posting user account cryptographic state to server");
    let request = SetKeyConnectorKeyRequestModel {
        key_connector_key_wrapped_user_key: Some(
            registration_crypto_result
                .key_connector_key_wrapped_user_key
                .to_string(),
        ),
        account_keys: Some(Box::new(registration_crypto_result.account_keys_request)),
        ..SetKeyConnectorKeyRequestModel::new(sso_org_identifier.to_string())
    };
    api_client
        .accounts_key_management_api()
        .post_set_key_connector_key(Some(request))
        .await
        .map_err(|e| {
            error!("Failed to post account cryptographic state to server: {e:?}");
            RegistrationError::Api
        })?;

    info!("User initialized!");
    // Note: This passing out of state and keys is temporary. Once SDK state management is more
    // mature, the account cryptographic state and keys should be set directly here.
    Ok(KeyConnectorRegistrationResult {
        account_cryptographic_state: registration_crypto_result.account_cryptographic_state,
        key_connector_key,
        key_connector_key_wrapped_user_key: registration_crypto_result
            .key_connector_key_wrapped_user_key,
        user_key: registration_crypto_result.user_key.to_encoded().into(),
    })
}

async fn post_key_to_key_connector(
    key_connector_api_client: &bitwarden_api_key_connector::apis::ApiClient,
    key_connector_key: &B64,
) -> Result<(), RegistrationError> {
    let request =
        bitwarden_api_key_connector::models::user_key_request_model::UserKeyKeyRequestModel {
            key: key_connector_key.to_string(),
        };

    let result = if key_connector_api_client
        .user_keys_api()
        .get_user_key()
        .await
        .is_ok()
    {
        info!("User's key connector key exists, updating");
        key_connector_api_client
            .user_keys_api()
            .put_user_key(request)
            .await
    } else {
        info!("User's key connector key does not exist, creating");
        key_connector_api_client
            .user_keys_api()
            .post_user_key(request)
            .await
    };

    result.map_err(|e| {
        error!("Failed to post key connector key to key connector server: {e:?}");
        RegistrationError::KeyConnectorApi
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

async fn internal_post_keys_for_jit_password_registration(
    registration_client: &RegistrationClient,
    api_client: &bitwarden_api_api::apis::ApiClient,
    request: JitMasterPasswordRegistrationRequest,
) -> Result<JitMasterPasswordRegistrationResponse, RegistrationError> {
    // First call crypto API to get all keys
    info!("Initializing account cryptography");
    let registration_crypto_result = registration_client
        .client
        .crypto()
        .make_user_jit_master_password_registration(
            request.user_id,
            request.master_password,
            request.salt,
            request.org_public_key,
        )
        .map_err(|_| RegistrationError::Crypto)?;

    // Post the generated keys to the API here. The user now has keys and is "registered", but
    // has no unlock method.
    let api_request = SetInitialPasswordRequestModel {
        account_keys: Some(Box::new(
            registration_crypto_result.account_keys_request.clone(),
        )),
        master_password_unlock: Some(Box::new(
            (&registration_crypto_result.master_password_unlock_data).into(),
        )),
        master_password_authentication: Some(Box::new(
            (&registration_crypto_result.master_password_authentication_data).into(),
        )),
        master_password_hint: request.master_password_hint,
        org_identifier: request.organization_sso_identifier,
        // TODO Deprecated fields below, to be removed with https://bitwarden.atlassian.net/browse/PM-27327
        kdf_parallelism: None,
        master_password_hash: None,
        key: None,
        keys: None,
        kdf: None,
        kdf_iterations: None,
        kdf_memory: None,
    };
    info!("Posting user account cryptographic state to server");
    api_client
        .accounts_api()
        .post_set_password(Some(api_request))
        .await
        .map_err(|e| {
            error!("Failed to post account keys: {e:?}");
            RegistrationError::Api
        })?;

    info!("Enrolling into admin account recovery");
    api_client
        .organization_users_api()
        .put_reset_password_enrollment(
            request.org_id.into(),
            request.user_id.into(),
            Some(OrganizationUserResetPasswordEnrollmentRequestModel {
                reset_password_key: Some(registration_crypto_result.reset_password_key.to_string()),
                master_password_hash: Some(
                    registration_crypto_result
                        .master_password_authentication_data
                        .master_password_authentication_hash
                        .to_string(),
                ),
            }),
        )
        .await
        .map_err(|e| {
            error!("Failed to enroll for reset password: {e:?}");
            RegistrationError::Api
        })?;

    info!("User initialized!");
    // Note: This passing out of state and keys is temporary. Once SDK state management is more
    // mature, the account cryptographic state and keys should be set directly here.
    Ok(JitMasterPasswordRegistrationResponse {
        account_cryptographic_state: registration_crypto_result.account_cryptographic_state,
        master_key: registration_crypto_result.master_key.to_base64(),
        master_password_unlock: registration_crypto_result.master_password_unlock_data,
        user_key: registration_crypto_result
            .user_key
            .to_encoded()
            .to_vec()
            .into(),
    })
}

/// Result of JIT master password registration process.
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct JitMasterPasswordRegistrationResponse {
    /// The account cryptographic state of the user
    pub account_cryptographic_state: WrappedAccountCryptographicState,
    /// The master password unlock data
    pub master_password_unlock: MasterPasswordUnlockData,
    /// The master key
    pub master_key: B64,
    /// The decrypted user key.
    pub user_key: B64,
}

/// Errors that can occur during user registration.
#[derive(Debug, Error)]
#[bitwarden_error(flat)]
pub enum RegistrationError {
    /// Key Connector API call failed.
    #[error("Key Connector Api call failed")]
    KeyConnectorApi,
    /// API call failed.
    #[error("Api call failed")]
    Api,
    /// Cryptography initialization failed.
    #[error("Cryptography initialization failed")]
    Crypto,
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use bitwarden_api_api::{
        apis::ApiClient,
        models::{DeviceResponseModel, KdfRequestModel, KdfType, KeysResponseModel},
    };
    use bitwarden_core::Client;
    use bitwarden_crypto::Kdf;

    use super::*;

    const TEST_USER_ID: &str = "060000fb-0922-4dd3-b170-6e15cb5df8c8";
    const TEST_ORG_ID: &str = "1bc9ac1e-f5aa-45f2-94bf-b181009709b8";
    const TEST_DEVICE_ID: &str = "test-device-id";
    const TEST_SSO_ORG_IDENTIFIER: &str = "test-org";

    const TEST_ORG_PUBLIC_KEY: &[u8] = &[
        48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0,
        48, 130, 1, 10, 2, 130, 1, 1, 0, 173, 4, 54, 63, 125, 12, 254, 38, 115, 34, 95, 164, 148,
        115, 86, 140, 129, 74, 19, 70, 212, 212, 130, 163, 105, 249, 101, 120, 154, 46, 194, 250,
        229, 242, 156, 67, 109, 179, 187, 134, 59, 235, 60, 107, 144, 163, 35, 22, 109, 230, 134,
        243, 44, 243, 79, 84, 76, 11, 64, 56, 236, 167, 98, 26, 30, 213, 143, 105, 52, 92, 129, 92,
        88, 22, 115, 135, 63, 215, 79, 8, 11, 183, 124, 10, 73, 231, 170, 110, 210, 178, 22, 100,
        76, 75, 118, 202, 252, 204, 67, 204, 152, 6, 244, 208, 161, 146, 103, 225, 233, 239, 88,
        195, 88, 150, 230, 111, 62, 142, 12, 157, 184, 155, 34, 84, 237, 111, 11, 97, 56, 152, 130,
        14, 72, 123, 140, 47, 137, 5, 97, 166, 4, 147, 111, 23, 65, 78, 63, 208, 198, 50, 161, 39,
        80, 143, 100, 194, 37, 252, 194, 53, 207, 166, 168, 250, 165, 121, 9, 207, 90, 36, 213,
        211, 84, 255, 14, 205, 114, 135, 217, 137, 105, 232, 58, 169, 222, 10, 13, 138, 203, 16,
        12, 122, 72, 227, 95, 160, 111, 54, 200, 198, 143, 156, 15, 143, 196, 50, 150, 204, 144,
        255, 162, 248, 50, 28, 47, 66, 9, 83, 158, 67, 9, 50, 147, 174, 147, 200, 199, 238, 190,
        248, 60, 114, 218, 32, 209, 120, 218, 17, 234, 14, 128, 192, 166, 33, 60, 73, 227, 108,
        201, 41, 160, 81, 133, 171, 205, 221, 2, 3, 1, 0, 1,
    ];

    #[tokio::test]
    async fn test_post_keys_for_tde_registration_success() {
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_post_keys()
                .once()
                .returning(move |_body| {
                    Ok(KeysResponseModel {
                        object: None,
                        key: None,
                        public_key: None,
                        private_key: None,
                        account_keys: None,
                    })
                });
            mock.organization_users_api
                .expect_put_reset_password_enrollment()
                .once()
                .returning(move |_org_id, _user_id, _body| Ok(()));
            mock.devices_api
                .expect_put_keys()
                .once()
                .returning(move |_device_id, _body| {
                    Ok(DeviceResponseModel {
                        object: None,
                        id: None,
                        name: None,
                        r#type: None,
                        identifier: None,
                        creation_date: None,
                        is_trusted: None,
                        encrypted_user_key: None,
                        encrypted_public_key: None,
                    })
                });
        });

        let request = TdeRegistrationRequest {
            org_id: TEST_ORG_ID.parse().unwrap(),
            org_public_key: TEST_ORG_PUBLIC_KEY.into(),
            user_id: TEST_USER_ID.parse().unwrap(),
            device_identifier: TEST_DEVICE_ID.to_string(),
            trust_device: true,
        };

        let result =
            internal_post_keys_for_tde_registration(&registration_client, &api_client, request)
                .await;

        assert!(result.is_ok());
        // Assert that the mock expectations were met
        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
            mock.organization_users_api.checkpoint();
            mock.devices_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_post_keys_for_tde_registration_trust_device_false() {
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_post_keys()
                .once()
                .returning(move |_body| {
                    Ok(KeysResponseModel {
                        object: None,
                        key: None,
                        public_key: None,
                        private_key: None,
                        account_keys: None,
                    })
                });
            mock.organization_users_api
                .expect_put_reset_password_enrollment()
                .once()
                .returning(move |_org_id, _user_id, _body| Ok(()));
            // Explicitly expect that put_keys is never called when trust_device is false
            mock.devices_api.expect_put_keys().never();
        });

        let request = TdeRegistrationRequest {
            org_id: TEST_ORG_ID.parse().unwrap(),
            org_public_key: TEST_ORG_PUBLIC_KEY.into(),
            user_id: TEST_USER_ID.parse().unwrap(),
            device_identifier: TEST_DEVICE_ID.to_string(),
            trust_device: false, // trust_device is false
        };

        let result =
            internal_post_keys_for_tde_registration(&registration_client, &api_client, request)
                .await;

        assert!(result.is_ok());
        // Assert that the mock expectations were met (put_keys should not have been called)
        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
            mock.organization_users_api.checkpoint();
            mock.devices_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_post_keys_for_tde_registration_post_keys_failure() {
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_post_keys()
                .once()
                .returning(move |_body| {
                    Err(bitwarden_api_api::apis::Error::Serde(
                        serde_json::Error::io(std::io::Error::other("API error")),
                    ))
                });
            // Subsequent API calls should not be made if post_keys fails
            mock.organization_users_api
                .expect_put_reset_password_enrollment()
                .never();
            mock.devices_api.expect_put_keys().never();
        });

        let request = TdeRegistrationRequest {
            org_id: TEST_ORG_ID.parse().unwrap(),
            org_public_key: TEST_ORG_PUBLIC_KEY.into(),
            user_id: TEST_USER_ID.parse().unwrap(),
            device_identifier: TEST_DEVICE_ID.to_string(),
            trust_device: true,
        };

        let result =
            internal_post_keys_for_tde_registration(&registration_client, &api_client, request)
                .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RegistrationError::Api));

        // Assert that the mock expectations were met
        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
            mock.organization_users_api.checkpoint();
            mock.devices_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_post_keys_for_tde_registration_reset_password_enrollment_failure() {
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_post_keys()
                .once()
                .returning(move |_body| {
                    Ok(KeysResponseModel {
                        object: None,
                        key: None,
                        public_key: None,
                        private_key: None,
                        account_keys: None,
                    })
                });
            mock.organization_users_api
                .expect_put_reset_password_enrollment()
                .once()
                .returning(move |_org_id, _user_id, _body| {
                    Err(bitwarden_api_api::apis::Error::Serde(
                        serde_json::Error::io(std::io::Error::other("API error")),
                    ))
                });
            // Device key enrollment should not be made if reset password enrollment fails
            mock.devices_api.expect_put_keys().never();
        });

        let request = TdeRegistrationRequest {
            org_id: TEST_ORG_ID.parse().unwrap(),
            org_public_key: TEST_ORG_PUBLIC_KEY.into(),
            user_id: TEST_USER_ID.parse().unwrap(),
            device_identifier: TEST_DEVICE_ID.to_string(),
            trust_device: true,
        };

        let result =
            internal_post_keys_for_tde_registration(&registration_client, &api_client, request)
                .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RegistrationError::Api));

        // Assert that the mock expectations were met
        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
            mock.organization_users_api.checkpoint();
            mock.devices_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_post_keys_for_tde_registration_device_keys_failure() {
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_post_keys()
                .once()
                .returning(move |_body| {
                    Ok(KeysResponseModel {
                        object: None,
                        key: None,
                        public_key: None,
                        private_key: None,
                        account_keys: None,
                    })
                });
            mock.organization_users_api
                .expect_put_reset_password_enrollment()
                .once()
                .returning(move |_org_id, _user_id, _body| Ok(()));
            mock.devices_api
                .expect_put_keys()
                .once()
                .returning(move |_device_id, _body| {
                    Err(bitwarden_api_api::apis::Error::Serde(
                        serde_json::Error::io(std::io::Error::other("API error")),
                    ))
                });
        });

        let request = TdeRegistrationRequest {
            org_id: TEST_ORG_ID.parse().unwrap(),
            org_public_key: TEST_ORG_PUBLIC_KEY.into(),
            user_id: TEST_USER_ID.parse().unwrap(),
            device_identifier: TEST_DEVICE_ID.to_string(),
            trust_device: true, // trust_device is true, so device enrollment should be attempted
        };

        let result =
            internal_post_keys_for_tde_registration(&registration_client, &api_client, request)
                .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RegistrationError::Api));

        // Assert that the mock expectations were met
        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
            mock.organization_users_api.checkpoint();
            mock.devices_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_post_keys_for_key_connector_registration_success() {
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_post_set_key_connector_key()
                .once()
                .returning(move |_body| Ok(()));
        });

        let key_connector_api_client =
            bitwarden_api_key_connector::apis::ApiClient::new_mocked(|mock| {
                mock.user_keys_api
                    .expect_get_user_key()
                    .once()
                    .returning(move || {
                        Err(bitwarden_api_key_connector::apis::Error::ResponseError(
                            bitwarden_api_key_connector::apis::ResponseContent {
                                status: reqwest::StatusCode::NOT_FOUND,
                                content: "Not Found".to_string(),
                            },
                        ))
                    });
                mock.user_keys_api
                    .expect_post_user_key()
                    .once()
                    .returning(move |_body| Ok(()));
            });

        let result = internal_post_keys_for_key_connector_registration(
            &registration_client,
            &api_client,
            &key_connector_api_client,
            TEST_SSO_ORG_IDENTIFIER.to_string(),
            UserId::new(uuid::uuid!(TEST_USER_ID)),
        )
        .await;
        assert!(result.is_ok());

        // Assert that the mock expectations were met
        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_key_management_api.checkpoint();
        }
        if let bitwarden_api_key_connector::apis::ApiClient::Mock(mut mock) =
            key_connector_api_client
        {
            mock.user_keys_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_post_keys_for_key_connector_registration_key_connector_api_failure() {
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let api_client = ApiClient::new_mocked(|mock| {
            // Should not be called if Key Connector API fails
            mock.accounts_key_management_api
                .expect_post_set_key_connector_key()
                .never();
        });

        let key_connector_api_client =
            bitwarden_api_key_connector::apis::ApiClient::new_mocked(|mock| {
                mock.user_keys_api
                    .expect_get_user_key()
                    .once()
                    .returning(move || {
                        Err(bitwarden_api_key_connector::apis::Error::ResponseError(
                            bitwarden_api_key_connector::apis::ResponseContent {
                                status: reqwest::StatusCode::NOT_FOUND,
                                content: "Not Found".to_string(),
                            },
                        ))
                    });
                mock.user_keys_api
                    .expect_post_user_key()
                    .once()
                    .returning(move |_body| {
                        Err(bitwarden_api_key_connector::apis::Error::Serde(
                            serde_json::Error::io(std::io::Error::other("API error")),
                        ))
                    });
            });

        let result = internal_post_keys_for_key_connector_registration(
            &registration_client,
            &api_client,
            &key_connector_api_client,
            TEST_SSO_ORG_IDENTIFIER.to_string(),
            UserId::new(uuid::uuid!(TEST_USER_ID)),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RegistrationError::KeyConnectorApi
        ));

        // Assert that the mock expectations were met
        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_key_management_api.checkpoint();
        }
        if let bitwarden_api_key_connector::apis::ApiClient::Mock(mut mock) =
            key_connector_api_client
        {
            mock.user_keys_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_post_keys_for_key_connector_registration_api_failure() {
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_post_set_key_connector_key()
                .once()
                .returning(move |_body| {
                    Err(bitwarden_api_api::apis::Error::Serde(
                        serde_json::Error::io(std::io::Error::other("API error")),
                    ))
                });
        });

        let key_connector_api_client =
            bitwarden_api_key_connector::apis::ApiClient::new_mocked(|mock| {
                mock.user_keys_api
                    .expect_get_user_key()
                    .once()
                    .returning(move || {
                        Err(bitwarden_api_key_connector::apis::Error::ResponseError(
                            bitwarden_api_key_connector::apis::ResponseContent {
                                status: reqwest::StatusCode::NOT_FOUND,
                                content: "Not Found".to_string(),
                            },
                        ))
                    });
                mock.user_keys_api
                    .expect_post_user_key()
                    .once()
                    .returning(move |_body| Ok(()));
            });

        let result = internal_post_keys_for_key_connector_registration(
            &registration_client,
            &api_client,
            &key_connector_api_client,
            TEST_SSO_ORG_IDENTIFIER.to_string(),
            UserId::new(uuid::uuid!(TEST_USER_ID)),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RegistrationError::Api));

        // Assert that the mock expectations were met
        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_key_management_api.checkpoint();
        }
        if let bitwarden_api_key_connector::apis::ApiClient::Mock(mut mock) =
            key_connector_api_client
        {
            mock.user_keys_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_post_keys_for_jit_password_registration_success() {
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let expected_hint = "test hint";

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_post_set_password()
                .once()
                .withf(move |body| {
                    if let Some(req) = body {
                        assert_eq!(req.org_identifier, TEST_SSO_ORG_IDENTIFIER);
                        assert_eq!(req.master_password_hint, Some(expected_hint.to_string()));
                        assert!(req.account_keys.is_some());
                        let account_keys = req.account_keys.as_ref().unwrap();
                        assert!(
                            account_keys
                                .user_key_encrypted_account_private_key
                                .is_some()
                        );
                        assert!(account_keys.account_public_key.is_some());
                        assert!(account_keys.public_key_encryption_key_pair.is_some());
                        let public_key_encryption_key_pair = account_keys
                            .public_key_encryption_key_pair
                            .as_ref()
                            .unwrap();
                        assert!(public_key_encryption_key_pair.public_key.is_some());
                        assert!(public_key_encryption_key_pair.signed_public_key.is_some());
                        assert!(public_key_encryption_key_pair.wrapped_private_key.is_some());
                        assert!(account_keys.signature_key_pair.is_some());
                        let signature_key_pair = account_keys.signature_key_pair.as_ref().unwrap();
                        assert_eq!(
                            signature_key_pair.signature_algorithm,
                            Some("ed25519".to_string())
                        );
                        assert!(signature_key_pair.verifying_key.is_some());
                        assert!(signature_key_pair.wrapped_signing_key.is_some());
                        assert!(account_keys.security_state.is_some());
                        let security_state = account_keys.security_state.as_ref().unwrap();
                        assert!(security_state.security_state.is_some());
                        assert_eq!(security_state.security_version, 2);
                        assert!(req.master_password_unlock.is_some());
                        let master_password_unlock = req.master_password_unlock.as_ref().unwrap();
                        assert_eq!(
                            master_password_unlock.salt,
                            Some("test@example.com".to_string())
                        );
                        assert_eq!(
                            master_password_unlock.kdf,
                            Box::new(KdfRequestModel {
                                kdf_type: KdfType::Argon2id,
                                iterations: 6,
                                memory: Some(32),
                                parallelism: Some(3),
                            })
                        );
                        assert!(master_password_unlock.master_key_wrapped_user_key.is_some());
                        assert!(req.master_password_authentication.is_some());
                        let master_password_authentication =
                            req.master_password_authentication.as_ref().unwrap();
                        assert_eq!(
                            master_password_authentication.salt,
                            Some("test@example.com".to_string())
                        );
                        assert_eq!(
                            master_password_authentication.kdf,
                            Box::new(KdfRequestModel {
                                kdf_type: KdfType::Argon2id,
                                iterations: 6,
                                memory: Some(32),
                                parallelism: Some(3),
                            })
                        );
                        assert!(
                            master_password_authentication
                                .master_password_authentication_hash
                                .is_some()
                        );
                        true
                    } else {
                        false
                    }
                })
                .returning(move |_body| Ok(()));
            mock.organization_users_api
                .expect_put_reset_password_enrollment()
                .once()
                .withf(move |org_id, user_id, body| {
                    assert_eq!(*org_id, uuid::uuid!(TEST_ORG_ID));
                    assert_eq!(*user_id, uuid::uuid!(TEST_USER_ID));
                    if let Some(enrollment_request) = body {
                        assert!(enrollment_request.reset_password_key.is_some());
                        assert!(enrollment_request.master_password_hash.is_some());
                        true
                    } else {
                        false
                    }
                })
                .returning(move |_org_id, _user_id, _body| Ok(()));
        });

        let request = JitMasterPasswordRegistrationRequest {
            org_id: TEST_ORG_ID.parse().unwrap(),
            org_public_key: TEST_ORG_PUBLIC_KEY.into(),
            organization_sso_identifier: TEST_SSO_ORG_IDENTIFIER.to_string(),
            user_id: TEST_USER_ID.parse().unwrap(),
            salt: "test@example.com".to_string(),
            master_password: "test-password-123".to_string(),
            master_password_hint: Some(expected_hint.to_string()),
        };

        let result = internal_post_keys_for_jit_password_registration(
            &registration_client,
            &api_client,
            request,
        )
        .await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(matches!(
            result.account_cryptographic_state,
            WrappedAccountCryptographicState::V2 { .. }
        ));
        assert_eq!(result.master_password_unlock.salt, "test@example.com");
        assert!(matches!(
            result.master_password_unlock.master_key_wrapped_user_key,
            EncString::Aes256Cbc_HmacSha256_B64 { .. }
        ));
        assert_eq!(
            result.master_password_unlock.kdf,
            Kdf::Argon2id {
                iterations: NonZeroU32::new(6).unwrap(),
                memory: NonZeroU32::new(32).unwrap(),
                parallelism: NonZeroU32::new(3).unwrap(),
            }
        );

        // Assert that the mock expectations were met
        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
            mock.organization_users_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_post_keys_for_jit_password_registration_api_failure() {
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_post_set_password()
                .once()
                .returning(move |_body| {
                    Err(bitwarden_api_api::apis::Error::Serde(
                        serde_json::Error::io(std::io::Error::other("API error")),
                    ))
                });
            mock.organization_users_api
                .expect_put_reset_password_enrollment()
                .never();
        });

        let request = JitMasterPasswordRegistrationRequest {
            org_id: TEST_ORG_ID.parse().unwrap(),
            org_public_key: TEST_ORG_PUBLIC_KEY.into(),
            organization_sso_identifier: TEST_SSO_ORG_IDENTIFIER.to_string(),
            user_id: TEST_USER_ID.parse().unwrap(),
            salt: "test@example.com".to_string(),
            master_password: "test-password-123".to_string(),
            master_password_hint: Some("test hint".to_string()),
        };

        let result = internal_post_keys_for_jit_password_registration(
            &registration_client,
            &api_client,
            request,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RegistrationError::Api));

        // Assert that the mock expectations were met
        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
            mock.organization_users_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_post_keys_for_jit_password_registration_reset_password_enrollment_failure() {
        let client = Client::new(None);
        let registration_client = RegistrationClient::new(client);

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_post_set_password()
                .once()
                .returning(move |_body| Ok(()));
            mock.organization_users_api
                .expect_put_reset_password_enrollment()
                .once()
                .returning(move |_org_id, _user_id, _body| {
                    Err(bitwarden_api_api::apis::Error::Serde(
                        serde_json::Error::io(std::io::Error::other("API error")),
                    ))
                });
        });

        let request = JitMasterPasswordRegistrationRequest {
            org_id: TEST_ORG_ID.parse().unwrap(),
            org_public_key: TEST_ORG_PUBLIC_KEY.into(),
            organization_sso_identifier: TEST_SSO_ORG_IDENTIFIER.to_string(),
            user_id: TEST_USER_ID.parse().unwrap(),
            salt: "test@example.com".to_string(),
            master_password: "test-password-123".to_string(),
            master_password_hint: Some("test hint".to_string()),
        };

        let result = internal_post_keys_for_jit_password_registration(
            &registration_client,
            &api_client,
            request,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RegistrationError::Api));

        // Assert that the mock expectations were met
        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_api.checkpoint();
            mock.organization_users_api.checkpoint();
        }
    }
}

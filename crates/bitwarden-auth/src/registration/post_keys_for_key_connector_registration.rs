//! Initializes a new cryptographic state for a user and posts it to the server; enrolls the
//! user to key connector unlock.
use bitwarden_api_api::models::SetKeyConnectorKeyRequestModel;
use bitwarden_core::key_management::account_cryptographic_state::WrappedAccountCryptographicState;
use bitwarden_crypto::EncString;
use bitwarden_encoding::B64;
use tracing::{error, info};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::registration::{RegistrationClient, RegistrationError};

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

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl RegistrationClient {
    /// Initializes a new cryptographic state for a user and posts it to the server; enrolls the
    /// user to key connector unlock.
    pub async fn post_keys_for_key_connector_registration(
        &self,
        key_connector_url: String,
        sso_org_identifier: String,
    ) -> Result<KeyConnectorRegistrationResult, RegistrationError> {
        let client = &self.client.internal;
        let configuration = &client.get_api_configurations();
        let key_connector_client = client.get_key_connector_client(key_connector_url);

        internal_post_keys_for_key_connector_registration(
            self,
            &configuration.api_client,
            &key_connector_client,
            sso_org_identifier,
        )
        .await
    }
}

async fn internal_post_keys_for_key_connector_registration(
    registration_client: &RegistrationClient,
    api_client: &bitwarden_api_api::apis::ApiClient,
    key_connector_api_client: &bitwarden_api_key_connector::apis::ApiClient,
    sso_org_identifier: String,
) -> Result<KeyConnectorRegistrationResult, RegistrationError> {
    // First call crypto API to get all keys
    info!("Initializing account cryptography");
    let registration_crypto_result = registration_client
        .client
        .crypto()
        .make_user_key_connector_registration()
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

#[cfg(test)]
mod tests {
    use bitwarden_api_api::apis::ApiClient;
    use bitwarden_core::Client;

    use super::*;

    const TEST_SSO_ORG_IDENTIFIER: &str = "test-org";

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
}

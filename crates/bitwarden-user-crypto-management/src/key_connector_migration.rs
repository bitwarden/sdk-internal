//! Client operations for migrating an initialized account to Key Connector unlock.

use bitwarden_api_api::models::KeyConnectorEnrollmentRequestModel;
use bitwarden_api_key_connector::models::user_key_request_model::UserKeyKeyRequestModel;
use bitwarden_core::key_management::SymmetricKeyId;
use bitwarden_crypto::{EncString, KeyConnectorKey};
use bitwarden_encoding::B64;
use bitwarden_error::bitwarden_error;
use thiserror::Error;
use tracing::{error, info};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::UserCryptoManagementClient;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl UserCryptoManagementClient {
    /// Migrates an initialized account to Key Connector unlock.
    ///
    /// Requires the client to be unlocked so the current user key is available in memory.
    pub async fn migrate_to_key_connector(
        &self,
        key_connector_url: String,
    ) -> Result<(), MigrateToKeyConnectorError> {
        let internal = &self.client.internal;
        let api_configuration = internal.get_api_configurations();
        let key_connector_api_client = internal.get_key_connector_client(key_connector_url);

        internal_migrate_to_key_connector(
            self,
            &api_configuration.api_client,
            &key_connector_api_client,
        )
        .await
    }
}

async fn internal_migrate_to_key_connector(
    user_crypto_management_client: &UserCryptoManagementClient,
    api_client: &bitwarden_api_api::apis::ApiClient,
    key_connector_api_client: &bitwarden_api_key_connector::apis::ApiClient,
) -> Result<(), MigrateToKeyConnectorError> {
    // A key-connector-migration does the following:
    // 1. Make a new key-connector-key. This is a randomly sampled symmetric key
    // 2. Wrap the user's current user-key with the key-connector-key
    // 3. Post the key-connector-key to the key-connector
    // 4. Post the wrapped user-key to the server. This will replace the existing "master key
    //    wrapped user-key".
    //
    // If the user-key is missing, we do not post the key-connector-key to the key-connector,
    // and instead return early.

    // Step 1: Make a new key-connector-key
    let key_connector_key = KeyConnectorKey::make();

    // Step 2: Wrap the user's current user key with the key connector key
    let key_connector_key_wrapped_user_key = {
        let key_store = user_crypto_management_client
            .client
            .internal
            .get_key_store();
        let ctx = key_store.context();
        key_connector_key
            .wrap_user_key(SymmetricKeyId::User, &ctx)
            .map_err(|_| MigrateToKeyConnectorError::UserKeyNotAvailable)?
    };

    // Step 3: Post the key connector key to the key connector server
    info!("Posting key connector key to key connector server");
    post_key_connector_key_to_key_connector(key_connector_api_client, key_connector_key).await?;

    // Step 4: Post the wrapped user key to the server and enroll the user into key connector
    info!("Posting wrapped user key for key connector migration");
    enroll_user_into_key_connector(api_client, key_connector_key_wrapped_user_key).await?;

    info!("Successfully migrated account to key connector unlock");
    Ok(())
}

async fn enroll_user_into_key_connector(
    api_client: &bitwarden_api_api::apis::ApiClient,
    key_connector_key_wrapped_user_key: EncString,
) -> Result<(), MigrateToKeyConnectorError> {
    let request = KeyConnectorEnrollmentRequestModel {
        key_connector_key_wrapped_user_key: Some(key_connector_key_wrapped_user_key.to_string()),
    };

    api_client
        .accounts_key_management_api()
        .post_enroll_to_key_connector(Some(request))
        .await
        .map_err(|e| {
            error!("Failed to post key connector migration request: {e:?}");
            MigrateToKeyConnectorError::Api
        })
}

async fn post_key_connector_key_to_key_connector(
    key_connector_api_client: &bitwarden_api_key_connector::apis::ApiClient,
    key_connector_key: KeyConnectorKey,
) -> Result<(), MigrateToKeyConnectorError> {
    let encoded_key_connector_key: B64 = key_connector_key.into();
    let request = UserKeyKeyRequestModel {
        key: encoded_key_connector_key.to_string(),
    };

    // Key-connector doesn't support PUT if the key does not exist, so
    // in this case we GET, then POST/PUT depending on the response.
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
        MigrateToKeyConnectorError::KeyConnectorApi
    })
}

#[derive(Debug, Error)]
#[bitwarden_error(flat)]
pub enum MigrateToKeyConnectorError {
    #[error("Current user key is not available")]
    UserKeyNotAvailable,
    #[error("Cryptographic error during key connector migration")]
    Crypto,
    #[error("Bitwarden API call failed during key connector migration")]
    Api,
    #[error("Key Connector API call failed during key connector migration")]
    KeyConnectorApi,
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::apis::ApiClient;
    use bitwarden_core::Client;
    use bitwarden_crypto::EncString;

    use super::*;

    fn unlocked_client() -> UserCryptoManagementClient {
        let client = Client::new(None);
        {
            let key_store = client.internal.get_key_store();
            let mut ctx = key_store.context_mut();
            let local_user_key =
                ctx.make_symmetric_key(bitwarden_crypto::SymmetricKeyAlgorithm::Aes256CbcHmac);
            let _ = ctx.persist_symmetric_key(local_user_key, SymmetricKeyId::User);
        }

        UserCryptoManagementClient::new(client)
    }

    #[tokio::test]
    async fn test_migrate_to_key_connector_success() {
        let user_crypto_management_client = unlocked_client();

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_post_enroll_to_key_connector()
                .once()
                .returning(move |body| {
                    let body = body.expect("body should be Some");
                    let wrapped_key = body
                        .key_connector_key_wrapped_user_key
                        .expect("key_connector_key_wrapped_user_key should be Some");
                    wrapped_key
                        .parse::<EncString>()
                        .expect("key_connector_key_wrapped_user_key should be a valid EncString");
                    Ok(())
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

        let result = internal_migrate_to_key_connector(
            &user_crypto_management_client,
            &api_client,
            &key_connector_api_client,
        )
        .await;

        assert!(result.is_ok());

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
    async fn test_migrate_to_key_connector_key_connector_api_failure() {
        let user_crypto_management_client = unlocked_client();

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_post_enroll_to_key_connector()
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

        let result = internal_migrate_to_key_connector(
            &user_crypto_management_client,
            &api_client,
            &key_connector_api_client,
        )
        .await;

        assert!(matches!(
            result,
            Err(MigrateToKeyConnectorError::KeyConnectorApi)
        ));

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
    async fn test_migrate_to_key_connector_api_failure() {
        let user_crypto_management_client = unlocked_client();

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_post_enroll_to_key_connector()
                .once()
                .returning(move |body| {
                    let body = body.expect("body should be Some");
                    let wrapped_key = body
                        .key_connector_key_wrapped_user_key
                        .expect("key_connector_key_wrapped_user_key should be Some");
                    wrapped_key
                        .parse::<EncString>()
                        .expect("key_connector_key_wrapped_user_key should be a valid EncString");
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

        let result = internal_migrate_to_key_connector(
            &user_crypto_management_client,
            &api_client,
            &key_connector_api_client,
        )
        .await;

        assert!(matches!(result, Err(MigrateToKeyConnectorError::Api)));

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
    async fn test_migrate_to_key_connector_user_key_not_available() {
        let user_crypto_management_client = UserCryptoManagementClient::new(Client::new(None));

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_post_enroll_to_key_connector()
                .never();
        });

        let key_connector_api_client =
            bitwarden_api_key_connector::apis::ApiClient::new_mocked(|mock| {
                mock.user_keys_api.expect_get_user_key().never();
                mock.user_keys_api.expect_post_user_key().never();
                mock.user_keys_api.expect_put_user_key().never();
            });

        let result = internal_migrate_to_key_connector(
            &user_crypto_management_client,
            &api_client,
            &key_connector_api_client,
        )
        .await;

        assert!(matches!(
            result,
            Err(MigrateToKeyConnectorError::UserKeyNotAvailable)
        ));

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

//! Client operations for migrating an initialized account to Key Connector unlock.

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
    let (_wrapped_user_key, key_connector_key): (EncString, B64) = {
        let key_store = user_crypto_management_client
            .client
            .internal
            .get_key_store();
        let ctx = key_store.context();

        #[allow(deprecated)]
        let user_key = ctx
            .dangerous_get_symmetric_key(SymmetricKeyId::User)
            .map_err(|_| MigrateToKeyConnectorError::UserKeyNotAvailable)?;

        let key_connector_key = KeyConnectorKey::make();
        let wrapped_user_key = key_connector_key
            .encrypt_user_key(user_key)
            .map_err(|_| MigrateToKeyConnectorError::CryptoError)?;

        (wrapped_user_key, key_connector_key.into())
    };

    info!("Posting key connector key to key connector server");
    post_key_to_key_connector(key_connector_api_client, &key_connector_key).await?;

    info!("Posting wrapped user key for key connector migration");
    api_client
        .accounts_key_management_api()
        .post_convert_to_key_connector()
        .await
        .map_err(|e| {
            error!("Failed to post key connector migration request: {e:?}");
            MigrateToKeyConnectorError::ApiError
        })?;

    info!("Successfully migrated account to key connector unlock");
    Ok(())
}

async fn post_key_to_key_connector(
    key_connector_api_client: &bitwarden_api_key_connector::apis::ApiClient,
    key_connector_key: &B64,
) -> Result<(), MigrateToKeyConnectorError> {
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
        MigrateToKeyConnectorError::KeyConnectorApiError
    })
}

#[derive(Debug, Error)]
#[bitwarden_error(flat)]
pub enum MigrateToKeyConnectorError {
    #[error("Current user key is not available")]
    UserKeyNotAvailable,
    #[error("Cryptographic error during key connector migration")]
    CryptoError,
    #[error("Bitwarden API call failed during key connector migration")]
    ApiError,
    #[error("Key Connector API call failed during key connector migration")]
    KeyConnectorApiError,
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::apis::ApiClient;
    use bitwarden_core::Client;

    use super::*;

    fn unlocked_client() -> UserCryptoManagementClient {
        let client = Client::new(None);
        {
            let key_store = client.internal.get_key_store();
            let mut ctx = key_store.context_mut();
            let local_user_key =
                ctx.make_symmetric_key(bitwarden_crypto::SymmetricKeyAlgorithm::Aes256CbcHmac);
            assert!(
                ctx.persist_symmetric_key(local_user_key, SymmetricKeyId::User)
                    .is_ok()
            );
        }

        UserCryptoManagementClient::new(client)
    }

    #[tokio::test]
    async fn test_migrate_to_key_connector_success() {
        let user_crypto_management_client = unlocked_client();

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

        let result = internal_migrate_to_key_connector(
            &user_crypto_management_client,
            &api_client,
            &key_connector_api_client,
        )
        .await;

        assert!(matches!(
            result,
            Err(MigrateToKeyConnectorError::KeyConnectorApiError)
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

        let result = internal_migrate_to_key_connector(
            &user_crypto_management_client,
            &api_client,
            &key_connector_api_client,
        )
        .await;

        assert!(matches!(result, Err(MigrateToKeyConnectorError::ApiError)));

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
                .expect_post_set_key_connector_key()
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

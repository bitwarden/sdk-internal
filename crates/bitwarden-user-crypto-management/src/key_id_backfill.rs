//! Record the user key's id with the server for accounts where it was never captured.
//!
//! Key ids were introduced after V2 user keys, so accounts created or upgraded before the server
//! started tracking them hold a key id in their key material that the server does not know about.
//!
//! This module adds a backfill functionality.

use bitwarden_api_api::models::SetUserKeyIdRequestModel;
use bitwarden_core::key_management::SymmetricKeySlotId;
use bitwarden_crypto::KeyId;
use bitwarden_error::bitwarden_error;
use thiserror::Error;
use tracing::{error, info};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::UserCryptoManagementClient;

/// Errors returned by the user key id backfill.
#[derive(Debug, Error)]
#[bitwarden_error(flat)]
pub enum KeyIdBackfillError {
    /// The user key is not in the key store, so the client is locked or not initialized.
    #[error("User key is not available in key store")]
    UserKeyNotAvailable,
    /// The current user key carries no key id
    #[error("The current user key has no key id to backfill")]
    NoKeyId,
    /// The key id the server knows is read from client-managed state, which needs a bridge.
    #[error("No state bridge registered, the user key id backfill is not supported")]
    StateBridgeNotRegistered,
    /// The API call recording the key id failed.
    #[error("API call failed during user key id backfill")]
    Api,
}

#[bitwarden_ffi::wasm_export]
#[cfg_attr(feature = "uniffi", uniffi::export(async_runtime = "tokio"))]
impl UserCryptoManagementClient {
    /// Returns whether the server is missing the id of the user's current user key.
    pub async fn user_key_id_needs_backfill(&self) -> Result<bool, KeyIdBackfillError> {
        let state_bridge = self.client.km_state_bridge();
        if !state_bridge.is_bridge_registered() {
            return Err(KeyIdBackfillError::StateBridgeNotRegistered);
        }

        // An id the server already knows needs no backfilling. A mismatch between it and the local
        // one would mean a key rotation the server has not seen, which is not this concern.
        if let Some(recorded) = state_bridge.get_user_key_id().await {
            info!(?recorded, "Server already knows the user key id");
            return Ok(false);
        }

        Ok(self.current_user_key_id()?.is_some())
    }

    /// Records the id of the user's current user key with the server, and stores it as the id the
    /// server knows.
    ///
    /// Safe to call when no backfill is needed, but [`Self::user_key_id_needs_backfill`] avoids the
    /// round trip.
    ///
    /// Requires the client to be unlocked so the current user key is available in memory.
    pub async fn user_key_id_backfill(&self) -> Result<(), KeyIdBackfillError> {
        let state_bridge = self.client.km_state_bridge();
        if !state_bridge.is_bridge_registered() {
            return Err(KeyIdBackfillError::StateBridgeNotRegistered);
        }

        let user_key_id = self
            .current_user_key_id()?
            .ok_or(KeyIdBackfillError::NoKeyId)?;

        info!("Recording the user key id with the server");
        self.client
            .internal
            .get_api_configurations()
            .api_client
            .accounts_key_management_api()
            .post_user_key_id(Some(SetUserKeyIdRequestModel {
                user_key_id: user_key_id.to_string(),
            }))
            .await
            .map_err(|e| {
                error!("Failed to post the user key id: {e:?}");
                KeyIdBackfillError::Api
            })?;

        // Written only after the server accepted it, so state never claims an id the server lacks.
        state_bridge.set_user_key_id(&user_key_id).await;

        Ok(())
    }
}

impl UserCryptoManagementClient {
    /// Reads the key id of the user key currently in the key store.
    fn current_user_key_id(&self) -> Result<Option<KeyId>, KeyIdBackfillError> {
        let key_store = self.client.internal.get_key_store();
        let ctx = key_store.context();

        if !ctx.has_symmetric_key(SymmetricKeySlotId::User) {
            return Err(KeyIdBackfillError::UserKeyNotAvailable);
        }

        Ok(ctx.get_symmetric_key_id(SymmetricKeySlotId::User))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bitwarden_api_api::apis::ApiClient;
    use bitwarden_core::{
        Client, client::internal::ApiConfigurations,
        key_management::state_bridge::test_support::InMemoryStateBridge,
    };
    use bitwarden_crypto::SymmetricKeyAlgorithm;

    use super::*;
    use crate::UserCryptoManagementClientExt;

    /// Builds a client holding a user key of the given algorithm, with a state bridge registered
    /// and its API calls served by `api_client`.
    fn client_with_user_key(algorithm: SymmetricKeyAlgorithm, api_client: ApiClient) -> Client {
        let client = Client::builder()
            .with_api_configurations(Arc::new(ApiConfigurations::from_api_client(api_client)))
            .build();
        client
            .km_state_bridge()
            .register_bridge(Box::new(InMemoryStateBridge::default()));
        {
            let key_store = client.internal.get_key_store();
            let mut ctx = key_store.context_mut();
            let local = ctx.make_symmetric_key(algorithm);
            ctx.persist_symmetric_key(local, SymmetricKeySlotId::User)
                .unwrap();
        }
        client
    }

    /// An API client that fails the test if any endpoint is called.
    fn no_api_calls() -> ApiClient {
        ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_post_user_key_id()
                .never();
        })
    }

    fn user_key_id(client: &Client) -> KeyId {
        client
            .internal
            .get_key_store()
            .context()
            .get_symmetric_key_id(SymmetricKeySlotId::User)
            .expect("a user key has a key id")
    }

    #[tokio::test]
    async fn test_needs_backfill_when_server_has_no_key_id() {
        let client = client_with_user_key(SymmetricKeyAlgorithm::XAes256Gcm, no_api_calls());

        assert!(
            client
                .user_crypto_management()
                .user_key_id_needs_backfill()
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_no_backfill_when_server_already_knows_the_key_id() {
        let client = client_with_user_key(SymmetricKeyAlgorithm::XAes256Gcm, no_api_calls());
        let key_id = user_key_id(&client);
        client.km_state_bridge().set_user_key_id(&key_id).await;

        assert!(
            !client
                .user_crypto_management()
                .user_key_id_needs_backfill()
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_needs_backfill_for_a_v1_user_key() {
        // A V1 key carries a key id as well, so it is backfilled like a V2 one.
        let client = client_with_user_key(SymmetricKeyAlgorithm::Aes256CbcHmac, no_api_calls());

        assert!(
            client
                .user_crypto_management()
                .user_key_id_needs_backfill()
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_needs_backfill_without_a_user_key_errors() {
        let client = Client::new(None);
        client
            .km_state_bridge()
            .register_bridge(Box::new(InMemoryStateBridge::default()));

        assert!(matches!(
            client
                .user_crypto_management()
                .user_key_id_needs_backfill()
                .await,
            Err(KeyIdBackfillError::UserKeyNotAvailable)
        ));
    }

    #[tokio::test]
    async fn test_needs_backfill_without_a_state_bridge_errors() {
        let client = Client::new(None);

        assert!(matches!(
            client
                .user_crypto_management()
                .user_key_id_needs_backfill()
                .await,
            Err(KeyIdBackfillError::StateBridgeNotRegistered)
        ));
    }

    /// Backfills a client holding a user key of the given algorithm, and asserts the key store's
    /// key id was both posted and stored.
    async fn assert_backfill_posts_and_stores(algorithm: SymmetricKeyAlgorithm) {
        // The posted id is checked against the key store's below, so the mock only records it.
        let posted = Arc::new(std::sync::Mutex::new(None));
        let recorder = posted.clone();
        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_post_user_key_id()
                .once()
                .returning(move |body| {
                    let body = body.expect("body should be Some");
                    *recorder.lock().unwrap() = Some(body.user_key_id);
                    Ok(())
                });
        });
        let client = client_with_user_key(algorithm, api_client);
        let expected = user_key_id(&client).to_string();

        client
            .user_crypto_management()
            .user_key_id_backfill()
            .await
            .unwrap();

        assert_eq!(posted.lock().unwrap().as_deref(), Some(expected.as_str()));
        let stored = client.km_state_bridge().get_user_key_id().await.unwrap();
        assert_eq!(stored.to_string(), expected);
    }

    #[tokio::test]
    async fn test_backfill_posts_the_key_id_and_stores_it() {
        assert_backfill_posts_and_stores(SymmetricKeyAlgorithm::XAes256Gcm).await;
    }

    #[tokio::test]
    async fn test_backfill_posts_the_key_id_and_stores_it_for_a_v1_user_key() {
        assert_backfill_posts_and_stores(SymmetricKeyAlgorithm::Aes256CbcHmac).await;
    }

    #[tokio::test]
    async fn test_backfill_leaves_state_untouched_when_the_api_fails() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_post_user_key_id()
                .once()
                .returning(|_| {
                    Err(bitwarden_api_api::apis::Error::Response(
                        bitwarden_api_api::apis::ResponseContent {
                            status: reqwest::StatusCode::BAD_REQUEST,
                            message: "Bad Request".to_string(),
                        },
                    ))
                });
        });
        let client = client_with_user_key(SymmetricKeyAlgorithm::XAes256Gcm, api_client);

        assert!(matches!(
            client.user_crypto_management().user_key_id_backfill().await,
            Err(KeyIdBackfillError::Api)
        ));
        assert!(client.km_state_bridge().get_user_key_id().await.is_none());
    }
}

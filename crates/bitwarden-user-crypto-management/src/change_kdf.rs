//! Client operation for changing the account's KDF (key derivation function) settings.

use bitwarden_api_api::models::ChangeKdfRequestModel;
use bitwarden_core::{
    ApiError, NotAuthenticatedError,
    key_management::{
        MasterPasswordAuthenticationData, MasterPasswordError, MasterPasswordUnlockData,
        SymmetricKeySlotId,
    },
};
use bitwarden_crypto::Kdf;
use bitwarden_error::bitwarden_error;
use thiserror::Error;
use tracing::error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::UserCryptoManagementClient;

#[bitwarden_ffi::wasm_export]
#[cfg_attr(feature = "uniffi", uniffi::export(async_runtime = "tokio"))]
impl UserCryptoManagementClient {
    /// Changes the account's KDF settings, and sets them on the server.
    pub async fn change_kdf(&self, password: String, new_kdf: Kdf) -> Result<(), ChangeKdfError> {
        let bridge = self.client.km_state_bridge();

        let current_unlock_data = bridge
            .get_masterpassword_unlock_data()
            .await
            .ok_or(ChangeKdfError::MissingMasterPasswordUnlockData)?;
        let salt = current_unlock_data.salt;
        let current_kdf = current_unlock_data.kdf;

        // Re-derive the authentication and unlock data. The key store context must not be held
        // across the await on the server request below, so it is scoped to this block.
        let (old_authentication_data, authentication_data, unlock_data) = {
            let ctx = self.client.internal.get_key_store().context();

            let old_authentication_data =
                MasterPasswordAuthenticationData::derive(&password, &current_kdf, &salt)?;
            let authentication_data =
                MasterPasswordAuthenticationData::derive(&password, &new_kdf, &salt)?;
            let unlock_data = MasterPasswordUnlockData::derive(
                &password,
                &new_kdf,
                &salt,
                SymmetricKeySlotId::User,
                &ctx,
            )?;

            (old_authentication_data, authentication_data, unlock_data)
        };

        // Build and post the change-KDF request to the server. The old authentication hash proves
        // possession of the current password; the new authentication and unlock data replace it.
        let request = ChangeKdfRequestModel {
            master_password_hash: old_authentication_data
                .master_password_authentication_hash
                .to_string(),
            authentication_data: Box::new((&authentication_data).into()),
            unlock_data: Box::new((&unlock_data).into()),
        };

        self.client
            .internal
            .get_api_configurations()
            .api_client
            .accounts_api()
            .post_kdf(Some(request))
            .await
            .map_err(|e| {
                error!("Failed to post change-kdf request: {e:?}");
                ApiError::from(e)
            })?;

        // Persist the new unlock data and KDF config to client-managed state via the state bridge,
        // then update the KDF held in the internal client so in-memory state stays consistent.
        bridge.set_masterpassword_unlock_data(&unlock_data).await;
        bridge.set_kdf_config(&new_kdf).await;
        self.client
            .internal
            .set_user_master_password_unlock(unlock_data)
            .await?;

        Ok(())
    }
}

/// Errors that can occur while changing the account KDF settings.
#[derive(Debug, Error)]
#[bitwarden_error(flat)]
pub enum ChangeKdfError {
    /// Deriving the new authentication or unlock data failed.
    #[error(transparent)]
    MasterPassword(#[from] MasterPasswordError),
    /// The current master-password unlock data is not available in the state bridge.
    #[error("Master password unlock data is not available")]
    MissingMasterPasswordUnlockData,
    /// The client is not authenticated with a master password.
    #[error(transparent)]
    NotAuthenticated(#[from] NotAuthenticatedError),
    /// The server rejected the change-KDF request.
    #[error(transparent)]
    Api(#[from] ApiError),
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use bitwarden_api_api::apis::ApiClient;
    use bitwarden_core::{
        Client,
        client::test_accounts::test_bitwarden_com_account,
        key_management::{
            MasterPasswordUnlockData, state_bridge::test_support::InMemoryStateBridge,
        },
    };
    use bitwarden_crypto::Kdf;

    use super::*;
    use crate::UserCryptoManagementClientExt;

    const TEST_PASSWORD: &str = "asdfasdfasdf";
    const TEST_EMAIL: &str = "test@bitwarden.com";
    // A valid EncString; only the salt/kdf of the seeded unlock data are used by derivation.
    const TEST_WRAPPED_USER_KEY: &str = "2.Q/2PhzcC7GdeiMHhWguYAQ==|GpqzVdr0go0ug5cZh1n+uixeBC3oC90CIe0hd/HWA/pTRDZ8ane4fmsEIcuc8eMKUt55Y2q/fbNzsYu41YTZzzsJUSeqVjT8/iTQtgnNdpo=|dwI+uyvZ1h/iZ03VQ+/wrGEFYVewBUUl/syYgjsNMbE=";

    fn new_kdf() -> Kdf {
        Kdf::PBKDF2 {
            iterations: NonZeroU32::new(700_000).unwrap(),
        }
    }

    // Sets the master-password unlock data in the state bridge to a fixed value for testing.
    async fn test_unlock_data(client: &Client) {
        let current_kdf = client.internal.get_kdf().await.unwrap();
        client
            .km_state_bridge()
            .set_masterpassword_unlock_data(&MasterPasswordUnlockData {
                kdf: current_kdf,
                master_key_wrapped_user_key: TEST_WRAPPED_USER_KEY.parse().unwrap(),
                salt: TEST_EMAIL.to_string(),
                contained_key_id: None,
            })
            .await;
    }

    #[tokio::test]
    async fn test_change_kdf_success_posts_and_persists() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_post_kdf()
                .once()
                .returning(|body| {
                    let body = body.expect("body should be Some");
                    // The unlock/authentication data must carry the new KDF settings.
                    assert_eq!(body.authentication_data.kdf.iterations, 700_000);
                    assert_eq!(body.unlock_data.kdf.iterations, 700_000);
                    assert!(!body.master_password_hash.is_empty());
                    Ok(())
                });
        });

        let client =
            Client::init_test_account_with_api_client(test_bitwarden_com_account(), api_client)
                .await;
        client
            .km_state_bridge()
            .register_bridge(Box::new(InMemoryStateBridge::default()));
        test_unlock_data(&client).await;

        client
            .user_crypto_management()
            .change_kdf(TEST_PASSWORD.to_string(), new_kdf())
            .await
            .unwrap();

        // The new KDF config and unlock data are persisted to state.
        let bridge = client.km_state_bridge();
        assert_eq!(bridge.get_kdf_config().await, Some(new_kdf()));
        let unlock = bridge
            .get_masterpassword_unlock_data()
            .await
            .expect("unlock data persisted");
        assert_eq!(unlock.kdf, new_kdf());
        // The internal client's KDF is updated as well.
        assert_eq!(client.internal.get_kdf().await.unwrap(), new_kdf());
    }

    #[tokio::test]
    async fn test_change_kdf_api_failure_does_not_persist() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_post_kdf()
                .once()
                .returning(|_body| Err(std::io::Error::other("Simulated error").into()));
        });

        let client =
            Client::init_test_account_with_api_client(test_bitwarden_com_account(), api_client)
                .await;
        client
            .km_state_bridge()
            .register_bridge(Box::new(InMemoryStateBridge::default()));
        test_unlock_data(&client).await;

        let current_kdf = client.internal.get_kdf().await.unwrap();

        let result = client
            .user_crypto_management()
            .change_kdf(TEST_PASSWORD.to_string(), new_kdf())
            .await;

        assert!(matches!(result, Err(ChangeKdfError::Api(_))));
        // The KDF config is untouched when the server call fails.
        assert_eq!(client.km_state_bridge().get_kdf_config().await, None);
        assert_eq!(client.internal.get_kdf().await.unwrap(), current_kdf);
    }

    #[tokio::test]
    async fn test_change_kdf_missing_unlock_data_errors() {
        let api_client = ApiClient::new_mocked(|_mock| {});
        let client =
            Client::init_test_account_with_api_client(test_bitwarden_com_account(), api_client)
                .await;
        client
            .km_state_bridge()
            .register_bridge(Box::new(InMemoryStateBridge::default()));

        let result = client
            .user_crypto_management()
            .change_kdf(TEST_PASSWORD.to_string(), new_kdf())
            .await;

        assert!(matches!(
            result,
            Err(ChangeKdfError::MissingMasterPasswordUnlockData)
        ));
    }
}

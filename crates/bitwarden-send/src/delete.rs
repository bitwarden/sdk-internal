use bitwarden_core::ApiError;
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{Send, SendId, send_client::SendClient};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum DeleteSendError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

async fn delete_send<R: Repository<Send> + ?Sized>(
    api_client: &bitwarden_api_api::apis::ApiClient,
    repository: &R,
    send_id: SendId,
) -> Result<(), DeleteSendError> {
    api_client
        .sends_api()
        .delete(&send_id.to_string())
        .await
        .map_err(ApiError::from)?;

    repository.remove(send_id).await?;

    Ok(())
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl SendClient {
    /// Delete a [Send] from the server and remove it from local state.
    pub async fn delete(&self, send_id: SendId) -> Result<(), DeleteSendError> {
        let config = self.client.internal.get_api_configurations();
        let repository = self.get_repository()?;

        delete_send(&config.api_client, repository.as_ref(), send_id).await
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::apis::ApiClient;
    use bitwarden_core::key_management::{KeyIds, SymmetricKeyId};
    use bitwarden_crypto::{KeyStore, SymmetricKeyAlgorithm};
    use bitwarden_test::MemoryRepository;
    use uuid::uuid;

    use super::*;
    use crate::{AuthType, Send, SendId, SendTextView, SendType, SendView};

    async fn make_store_with_send(
        send_id: uuid::Uuid,
    ) -> (KeyStore<KeyIds>, MemoryRepository<Send>) {
        let store: KeyStore<KeyIds> = KeyStore::default();
        {
            let mut ctx = store.context_mut();
            let local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(local_key_id, SymmetricKeyId::User)
                .unwrap();
        }

        let repository = MemoryRepository::<Send>::default();
        let send_view = SendView {
            id: None,
            access_id: None,
            name: "Test Send".to_string(),
            notes: None,
            key: None,
            new_password: None,
            has_password: false,
            r#type: SendType::Text,
            file: None,
            text: Some(SendTextView {
                text: Some("Secret text".to_string()),
                hidden: false,
            }),
            max_access_count: None,
            access_count: 0,
            disabled: false,
            hide_email: false,
            revision_date: "2025-01-01T00:00:00Z".parse().unwrap(),
            deletion_date: "2025-01-10T00:00:00Z".parse().unwrap(),
            expiration_date: None,
            emails: Vec::new(),
            auth_type: AuthType::None,
        };
        let mut send = store.encrypt(send_view).unwrap();
        send.id = Some(SendId::new(send_id));
        repository.set(SendId::new(send_id), send).await.unwrap();

        (store, repository)
    }

    #[tokio::test]
    async fn test_delete_send() {
        let send_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");
        let (_store, repository) = make_store_with_send(send_id).await;

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.sends_api
                .expect_delete()
                .returning(move |_id| Ok(()))
                .once();
        });

        let result = delete_send(&api_client, &repository, SendId::new(send_id)).await;

        assert!(result.is_ok());
        assert!(
            repository
                .get(SendId::new(send_id))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_delete_send_http_error() {
        let send_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");
        let (_store, repository) = make_store_with_send(send_id).await;

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.sends_api
                .expect_delete()
                .returning(move |_id| {
                    Err(bitwarden_api_api::apis::Error::Io(std::io::Error::other(
                        "Simulated error",
                    )))
                })
                .once();
        });

        let result = delete_send(&api_client, &repository, SendId::new(send_id)).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DeleteSendError::Api(_)));
        // Send should still be in the repository since API call failed
        assert!(
            repository
                .get(SendId::new(send_id))
                .await
                .unwrap()
                .is_some()
        );
    }
}

use bitwarden_core::{ApiError, MissingFieldError, key_management::KeyIds, require};
use bitwarden_crypto::{CryptoError, KeyStore};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{Send, SendId, SendView, error::SendParseError, send_client::SendClient};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum RemoveSendPasswordError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    #[error(transparent)]
    SendParse(#[from] SendParseError),
}

async fn remove_send_password<R: Repository<Send> + ?Sized>(
    key_store: &KeyStore<KeyIds>,
    api_client: &bitwarden_api_api::apis::ApiClient,
    repository: &R,
    send_id: SendId,
) -> Result<SendView, RemoveSendPasswordError> {
    let resp = api_client
        .sends_api()
        .put_remove_password(&send_id.to_string())
        .await
        .map_err(ApiError::from)?;

    let send: Send = resp.try_into()?;

    repository.set(require!(send.id), send.clone()).await?;

    Ok(key_store.decrypt(&send)?)
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl SendClient {
    /// Remove the password from a [Send], saving the updated state to the server and local state.
    pub async fn remove_password(
        &self,
        send_id: SendId,
    ) -> Result<SendView, RemoveSendPasswordError> {
        let key_store = self.client.internal.get_key_store();
        let config = self.client.internal.get_api_configurations();
        let repository = self.get_repository()?;

        remove_send_password(key_store, &config.api_client, repository.as_ref(), send_id).await
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{apis::ApiClient, models::SendResponseModel};
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
    async fn test_remove_send_password() {
        let send_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");
        let (store, repository) = make_store_with_send(send_id).await;

        // Get the encrypted fields from the stored send so the mock can return a realistic response
        let stored = repository.get(SendId::new(send_id)).await.unwrap().unwrap();
        let stored_name = stored.name.to_string();
        let stored_key = stored.key.to_string();
        let stored_deletion_date = stored.deletion_date.to_rfc3339();

        let api_client = ApiClient::new_mocked(move |mock| {
            let name = stored_name.clone();
            let key = stored_key.clone();
            let deletion_date = stored_deletion_date.clone();
            mock.sends_api
                .expect_put_remove_password()
                .returning(move |_id| {
                    Ok(SendResponseModel {
                        id: Some(send_id),
                        name: Some(name.clone()),
                        revision_date: Some("2025-01-02T00:00:00Z".to_string()),
                        object: Some("send".to_string()),
                        access_id: None,
                        r#type: Some(bitwarden_api_api::models::SendType::Text),
                        auth_type: Some(bitwarden_api_api::models::AuthType::None),
                        notes: None,
                        file: None,
                        text: None,
                        key: Some(key.clone()),
                        max_access_count: None,
                        access_count: Some(0),
                        password: None,
                        emails: None,
                        disabled: Some(false),
                        expiration_date: None,
                        deletion_date: Some(deletion_date.clone()),
                        hide_email: Some(false),
                    })
                })
                .once();
        });

        let result =
            remove_send_password(&store, &api_client, &repository, SendId::new(send_id)).await;

        assert!(result.is_ok());
        let view = result.unwrap();
        assert_eq!(view.id, Some(SendId::new(send_id)));
        assert!(!view.has_password);
        assert_eq!(view.auth_type, AuthType::None);
    }

    #[tokio::test]
    async fn test_remove_send_password_http_error() {
        let send_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");
        let (store, repository) = make_store_with_send(send_id).await;

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.sends_api
                .expect_put_remove_password()
                .returning(move |_id| {
                    Err(bitwarden_api_api::apis::Error::Io(std::io::Error::other(
                        "Simulated error",
                    )))
                })
                .once();
        });

        let result =
            remove_send_password(&store, &api_client, &repository, SendId::new(send_id)).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RemoveSendPasswordError::Api(_)
        ));
    }
}

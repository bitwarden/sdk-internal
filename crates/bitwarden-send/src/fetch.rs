use bitwarden_core::{ApiError, MissingFieldError, require};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{Send, SendId, error::SendParseError, send_client::SendClient};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum FetchSendError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    #[error(transparent)]
    SendParse(#[from] SendParseError),
}

async fn fetch_send<R: Repository<Send> + ?Sized>(
    api_client: &bitwarden_api_api::apis::ApiClient,
    repository: &R,
    send_id: SendId,
) -> Result<Send, FetchSendError> {
    let resp = api_client.sends_api().get(&send_id.to_string()).await?;

    let send: Send = resp.try_into()?;

    repository.set(require!(send.id), send.clone()).await?;

    Ok(send)
}

#[bitwarden_ffi::wasm_export]
impl SendClient {
    /// Fetch a single [Send] by its ID from the server and persist it to local state.
    ///
    /// Unlike [`SendClient::get`], which only reads from local state, this makes a network request
    /// and refreshes the locally stored copy. Returns the still-encrypted [Send] — matching what a
    /// sync-notification diff needs to compare `revision_date` and update encrypted state without
    /// a decrypt round-trip — rather than a [`SendView`](crate::SendView); callers that want the
    /// decrypted form can pass the result to [`SendClient::decrypt`].
    pub async fn fetch(&self, send_id: SendId) -> Result<Send, FetchSendError> {
        let config = self.client.internal.get_api_configurations();
        let repository = self.get_repository()?;

        fetch_send(&config.api_client, repository.as_ref(), send_id).await
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{apis::ApiClient, models::SendResponseModel};
    use bitwarden_core::key_management::{KeySlotIds, SymmetricKeySlotId};
    use bitwarden_crypto::{KeyStore, SymmetricKeyAlgorithm};
    use bitwarden_test::MemoryRepository;
    use uuid::uuid;

    use super::*;
    use crate::{AuthType, SendTextView, SendType, SendView};

    /// Builds a key store with a user key and returns an encrypted send (not yet stored) so tests
    /// can hand realistic encrypted fields back through the mocked API.
    fn make_store_and_encrypted_send(send_id: uuid::Uuid) -> (KeyStore<KeySlotIds>, Send) {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        {
            let mut ctx = store.context_mut();
            let local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(local_key_id, SymmetricKeySlotId::User)
                .unwrap();
        }

        let send_view = SendView {
            id: None,
            access_id: None,
            name: "Test Send".to_string(),
            notes: Some("Test notes".to_string()),
            key: None,
            new_password: None,
            has_password: false,
            r#type: SendType::Text,
            file: None,
            text: Some(SendTextView {
                text: Some("Secret text".to_string()),
                hidden: false,
            }),
            data: None,
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

        (store, send)
    }

    #[tokio::test]
    async fn test_fetch_send() {
        let send_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");
        let (store, send) = make_store_and_encrypted_send(send_id);

        let name = send.name.to_string();
        let key = send.key.to_string();
        let text = send
            .text
            .as_ref()
            .and_then(|t| t.text.as_ref())
            .map(|t| t.to_string());
        let deletion_date = send.deletion_date.to_rfc3339();

        let api_client = ApiClient::new_mocked(move |mock| {
            let name = name.clone();
            let key = key.clone();
            let text = text.clone();
            let deletion_date = deletion_date.clone();
            mock.sends_api
                .expect_get()
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
                        text: Some(Box::new(bitwarden_api_api::models::SendTextModel {
                            text: text.clone(),
                            hidden: Some(false),
                        })),
                        data: None,
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

        let repository = MemoryRepository::<Send>::default();

        let result = fetch_send(&api_client, &repository, SendId::new(send_id))
            .await
            .unwrap();

        assert_eq!(result.id, Some(SendId::new(send_id)));
        assert_eq!(result.name, send.name);

        // The result is still encrypted, not a decrypted view: decrypting it (with the store that
        // has the matching key) reproduces the original plaintext send.
        let decrypted: SendView = store.decrypt(&result).unwrap();
        assert_eq!(decrypted.name, "Test Send");
        assert_eq!(
            decrypted.text,
            Some(SendTextView {
                text: Some("Secret text".to_string()),
                hidden: false,
            })
        );

        // The fetched send should have been persisted to the repository.
        assert!(
            repository
                .get(SendId::new(send_id))
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_fetch_send_http_error() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.sends_api
                .expect_get()
                .returning(move |_id| {
                    Err(bitwarden_api_api::ApiError::Io(std::io::Error::other(
                        "Simulated error",
                    )))
                })
                .once();
        });

        let repository = MemoryRepository::<Send>::default();
        let send_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");

        let result = fetch_send(&api_client, &repository, SendId::new(send_id)).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FetchSendError::Api(_)));
    }
}

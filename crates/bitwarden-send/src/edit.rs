use bitwarden_core::{ApiError, MissingFieldError, key_management::KeyIds};
use bitwarden_crypto::{CryptoError, KeyStore};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError};
use thiserror::Error;
use uuid::Uuid;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    Send, SendView,
    create::SendAddEditRequest,
    error::{ItemNotFoundError, SendParseError},
};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EditSendError {
    #[error(transparent)]
    ItemNotFound(#[from] ItemNotFoundError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    #[error(transparent)]
    Uuid(#[from] uuid::Error),
    #[error(transparent)]
    SendParse(#[from] SendParseError),
}

pub(super) async fn edit_send<R: Repository<Send> + ?Sized>(
    key_store: &KeyStore<KeyIds>,
    api_client: &bitwarden_api_api::apis::ApiClient,
    repository: &R,
    send_id: Uuid,
    request: SendAddEditRequest,
) -> Result<SendView, EditSendError> {
    let id = send_id.to_string();

    // Verify the send we're updating exists
    repository.get(id.clone()).await?.ok_or(ItemNotFoundError)?;

    let send_request = key_store.encrypt(request)?;

    let resp = api_client
        .sends_api()
        .put(&id, Some(send_request))
        .await
        .map_err(ApiError::from)?;

    let send: Send = resp.try_into()?;

    debug_assert!(send.id.unwrap_or_default() == send_id);

    repository.set(id, send.clone()).await?;

    Ok(key_store.decrypt(&send)?)
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{apis::ApiClient, models::SendResponseModel};
    use bitwarden_core::key_management::SymmetricKeyId;
    use bitwarden_crypto::SymmetricKeyAlgorithm;
    use bitwarden_test::MemoryRepository;
    use chrono::{DateTime, Utc};
    use uuid::uuid;

    use super::*;
    use crate::{AuthType, SendTextView, SendType};

    #[tokio::test]
    async fn test_edit_send() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        {
            let mut ctx = store.context_mut();
            let local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(local_key_id, SymmetricKeyId::User)
                .unwrap();
        }

        let send_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");

        // Pre-populate the repository with an existing send by encrypting a SendView
        let repository = MemoryRepository::<Send>::default();
        let existing_send_view = SendView {
            id: None, // No ID initially to allow key generation
            access_id: None,
            name: "original".to_string(),
            notes: Some("original notes".to_string()),
            key: None, // Will be generated
            new_password: None,
            has_password: false,
            r#type: SendType::Text,
            file: None,
            text: Some(SendTextView {
                text: Some("original text".to_string()),
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
        let mut existing_send = store.encrypt(existing_send_view).unwrap();
        existing_send.id = Some(send_id); // Set the ID after encryption
        repository
            .set(send_id.to_string(), existing_send)
            .await
            .unwrap();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.sends_api
                .expect_put()
                .returning(move |_id, model| {
                    let model = model.unwrap();
                    Ok(SendResponseModel {
                        id: Some(send_id),
                        name: model.name,
                        revision_date: Some("2025-01-02T00:00:00Z".to_string()),
                        object: Some("send".to_string()),
                        access_id: None,
                        r#type: model.r#type,
                        auth_type: model.auth_type,
                        notes: model.notes,
                        file: model.file,
                        text: model.text,
                        key: Some(model.key),
                        max_access_count: model.max_access_count,
                        access_count: Some(0),
                        password: model.password,
                        emails: model.emails,
                        disabled: Some(model.disabled),
                        expiration_date: model.expiration_date,
                        deletion_date: Some(model.deletion_date),
                        hide_email: model.hide_email,
                    })
                })
                .once();
        });

        let result = edit_send(
            &store,
            &api_client,
            &repository,
            send_id,
            SendAddEditRequest {
                name: "updated".to_string(),
                notes: Some("updated notes".to_string()),
                key: None,
                password: None,
                r#type: SendType::Text,
                file: None,
                text: Some(SendTextView {
                    text: Some("updated text".to_string()),
                    hidden: false,
                }),
                max_access_count: None,
                disabled: false,
                hide_email: false,
                deletion_date: "2025-01-10T00:00:00Z".parse().unwrap(),
                expiration_date: None,
                emails: Vec::new(),
                auth_type: AuthType::None,
            },
        )
        .await
        .unwrap();

        // Verify the result
        assert_eq!(result.id, Some(send_id));
        assert_eq!(result.name, "updated");
        assert_eq!(result.notes, Some("updated notes".to_string()));
        assert!(result.key.is_some(), "Expected a key");
        assert_eq!(result.revision_date, "2025-01-02T00:00:00Z".parse::<DateTime<Utc>>().unwrap());

        // Confirm the send was updated in the repository
        let stored = repository.get(send_id.to_string()).await.unwrap().unwrap();
        assert_eq!(
            store
                .decrypt::<SymmetricKeyId, Send, SendView>(&stored)
                .unwrap()
                .name,
            "updated"
        );
    }

    #[tokio::test]
    async fn test_edit_send_not_found() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        {
            let mut ctx = store.context_mut();
            let local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(local_key_id, SymmetricKeyId::User)
                .unwrap();
        }

        let send_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");
        let repository = MemoryRepository::<Send>::default();
        let api_client = ApiClient::new_mocked(move |_mock| {});

        let result = edit_send(
            &store,
            &api_client,
            &repository,
            send_id,
            SendAddEditRequest {
                name: "test".to_string(),
                notes: None,
                key: None,
                password: None,
                r#type: SendType::Text,
                file: None,
                text: Some(SendTextView {
                    text: Some("test".to_string()),
                    hidden: false,
                }),
                max_access_count: None,
                disabled: false,
                hide_email: false,
                deletion_date: "2025-01-10T00:00:00Z".parse().unwrap(),
                expiration_date: None,
                emails: Vec::new(),
                auth_type: AuthType::None,
            },
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EditSendError::ItemNotFound(_)));
    }

    #[tokio::test]
    async fn test_edit_send_http_error() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        {
            let mut ctx = store.context_mut();
            let local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(local_key_id, SymmetricKeyId::User)
                .unwrap();
        }

        let send_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");

        // Pre-populate the repository with an existing send by encrypting a SendView
        let repository = MemoryRepository::<Send>::default();
        let existing_send_view = SendView {
            id: None, // No ID initially to allow key generation
            access_id: None,
            name: "original".to_string(),
            notes: Some("original notes".to_string()),
            key: None, // Will be generated
            new_password: None,
            has_password: false,
            r#type: SendType::Text,
            file: None,
            text: Some(SendTextView {
                text: Some("original text".to_string()),
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
        let mut existing_send = store.encrypt(existing_send_view).unwrap();
        existing_send.id = Some(send_id); // Set the ID after encryption
        repository
            .set(send_id.to_string(), existing_send)
            .await
            .unwrap();

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.sends_api.expect_put().returning(move |_id, _model| {
                Err(bitwarden_api_api::apis::Error::Io(std::io::Error::other(
                    "Simulated error",
                )))
            });
        });

        let result = edit_send(
            &store,
            &api_client,
            &repository,
            send_id,
            SendAddEditRequest {
                name: "test".to_string(),
                notes: None,
                key: None,
                password: None,
                r#type: SendType::Text,
                file: None,
                text: Some(SendTextView {
                    text: Some("test".to_string()),
                    hidden: false,
                }),
                max_access_count: None,
                disabled: false,
                hide_email: false,
                deletion_date: "2025-01-10T00:00:00Z".parse().unwrap(),
                expiration_date: None,
                emails: Vec::new(),
                auth_type: AuthType::None,
            },
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EditSendError::Api(_)));
    }
}


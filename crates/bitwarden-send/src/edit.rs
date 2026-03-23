use bitwarden_core::{
    ApiError, MissingFieldError,
    key_management::{KeyIds, SymmetricKeyId},
};
use bitwarden_crypto::{
    CompositeEncryptable, CryptoError, IdentifyKey, KeyStore, KeyStoreContext, OctetStreamBytes,
    PrimitiveEncryptable,
};
use bitwarden_encoding::B64Url;
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;
use uuid::Uuid;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    Send, SendAuthType, SendId, SendView, SendViewType,
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
    #[error("Server returned Send with ID {returned:?} but expected {expected}")]
    IdMismatch {
        expected: Uuid,
        returned: Option<Uuid>,
    },
}

/// Request model for editing an existing Send.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SendEditRequest {
    /// The name of the Send.
    pub name: String,
    /// Optional notes visible to the sender.
    pub notes: Option<String>,

    /// The type and content of the Send.
    pub view_type: SendViewType,

    /// Maximum number of times the Send can be accessed.
    pub max_access_count: Option<u32>,
    /// Whether the Send is disabled and cannot be accessed.
    pub disabled: bool,
    /// Whether to hide the sender's email from recipients.
    pub hide_email: bool,

    /// Date and time when the Send will be permanently deleted.
    pub deletion_date: DateTime<Utc>,
    /// Optional date and time when the Send expires and can no longer be accessed.
    pub expiration_date: Option<DateTime<Utc>>,

    /// Authentication method for accessing this Send.
    /// Use `SendAuthType::None` for no authentication,
    /// `SendAuthType::Password` for password protection, or
    /// `SendAuthType::Emails` for email OTP authentication.
    pub auth: SendAuthType,
}

/// Internal helper struct that includes the send key for encryption.
/// The key is retrieved from state during edit operations.
#[derive(Debug)]
struct SendEditRequestWithKey {
    request: SendEditRequest,
    send_key: String,
}

impl CompositeEncryptable<KeyIds, SymmetricKeyId, bitwarden_api_api::models::SendRequestModel>
    for SendEditRequestWithKey
{
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<bitwarden_api_api::models::SendRequestModel, CryptoError> {
        // Decode the send key from the existing send
        let k = B64Url::try_from(self.send_key.as_str())
            .map_err(|_| CryptoError::InvalidKey)?
            .as_bytes()
            .to_vec();

        // Derive the shareable send key for encrypting content
        let send_key = Send::derive_shareable_key(ctx, &k)?;

        let (send_type, file, text) = self
            .request
            .view_type
            .clone()
            .encrypt_composite(ctx, send_key)?;

        let (password, emails) = self.request.auth.auth_data(&k);

        Ok(bitwarden_api_api::models::SendRequestModel {
            r#type: Some(send_type),
            auth_type: Some(self.request.auth.auth_type().into()),
            file_length: None,
            name: Some(self.request.name.encrypt(ctx, send_key)?.to_string()),
            notes: self
                .request
                .notes
                .as_ref()
                .map(|n| n.encrypt(ctx, send_key))
                .transpose()?
                .map(|e| e.to_string()),
            // Encrypt the send key itself with the user key
            key: OctetStreamBytes::from(k).encrypt(ctx, key)?.to_string(),
            max_access_count: self.request.max_access_count.map(|c| c as i32),
            expiration_date: self.request.expiration_date.map(|d| d.to_rfc3339()),
            deletion_date: self.request.deletion_date.to_rfc3339(),
            file,
            text,
            password,
            emails,
            disabled: self.request.disabled,
            hide_email: Some(self.request.hide_email),
        })
    }
}

impl IdentifyKey<SymmetricKeyId> for SendEditRequestWithKey {
    fn key_identifier(&self) -> SymmetricKeyId {
        SymmetricKeyId::User
    }
}

pub(super) async fn edit_send<R: Repository<Send> + ?Sized>(
    key_store: &KeyStore<KeyIds>,
    api_client: &bitwarden_api_api::apis::ApiClient,
    repository: &R,
    send_id: Uuid,
    request: SendEditRequest,
) -> Result<SendView, EditSendError> {
    let id = send_id.to_string();

    // Retrieve the existing send to get its key (keys cannot be modified during edit)
    let existing_send = repository
        .get(SendId::new(send_id))
        .await?
        .ok_or(ItemNotFoundError)?;

    // Decrypt to get the key - we only need the key field
    let existing_send_view: SendView = key_store.decrypt(&existing_send)?;
    let send_key = existing_send_view.key.ok_or(MissingFieldError("key"))?;

    // Create the wrapper with the key from the existing send
    let request_with_key = SendEditRequestWithKey { request, send_key };

    let send_request = key_store.encrypt(request_with_key)?;

    let resp = api_client
        .sends_api()
        .put(&id, Some(send_request))
        .await
        .map_err(ApiError::from)?;

    let send: Send = resp.try_into()?;

    // Verify the server returned the correct send ID
    if send.id != Some(crate::send::SendId::new(send_id)) {
        return Err(EditSendError::IdMismatch {
            expected: send_id,
            returned: send.id.map(Into::into),
        });
    }

    repository.set(SendId::new(send_id), send.clone()).await?;

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
    use crate::{AuthType, SendTextView, SendType, SendViewType};

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
            key: None, // Generates a new key when first encrypted
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
        existing_send.id = Some(crate::send::SendId::new(send_id)); // Set the ID after encryption
        repository
            .set(SendId::new(send_id), existing_send)
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
            SendEditRequest {
                name: "updated".to_string(),
                notes: Some("updated notes".to_string()),
                view_type: SendViewType::Text(SendTextView {
                    text: Some("updated text".to_string()),
                    hidden: false,
                }),
                max_access_count: None,
                disabled: false,
                hide_email: false,
                deletion_date: "2025-01-10T00:00:00Z".parse().unwrap(),
                expiration_date: None,
                auth: SendAuthType::None,
            },
        )
        .await
        .unwrap();

        // Verify the result
        assert_eq!(result.id, Some(crate::send::SendId::new(send_id)));
        assert_eq!(result.name, "updated");
        assert_eq!(result.notes, Some("updated notes".to_string()));
        assert!(result.key.is_some(), "Expected a key");
        assert_eq!(
            result.revision_date,
            "2025-01-02T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );

        // Confirm the send was updated in the repository
        let stored = repository.get(SendId::new(send_id)).await.unwrap().unwrap();
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
            SendEditRequest {
                name: "test".to_string(),
                notes: None,
                view_type: SendViewType::Text(SendTextView {
                    text: Some("test".to_string()),
                    hidden: false,
                }),
                max_access_count: None,
                disabled: false,
                hide_email: false,
                deletion_date: "2025-01-10T00:00:00Z".parse().unwrap(),
                expiration_date: None,
                auth: SendAuthType::None,
            },
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EditSendError::ItemNotFound(_)
        ));
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
            key: None, // Generates a new key when first encrypted
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
        existing_send.id = Some(crate::send::SendId::new(send_id)); // Set the ID after encryption
        repository
            .set(SendId::new(send_id), existing_send)
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
            SendEditRequest {
                name: "test".to_string(),
                notes: None,
                view_type: SendViewType::Text(SendTextView {
                    text: Some("test".to_string()),
                    hidden: false,
                }),
                max_access_count: None,
                disabled: false,
                hide_email: false,
                deletion_date: "2025-01-10T00:00:00Z".parse().unwrap(),
                expiration_date: None,
                auth: SendAuthType::None,
            },
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EditSendError::Api(_)));
    }
}

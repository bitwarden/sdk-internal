use bitwarden_core::{
    ApiError, MissingFieldError,
    key_management::{KeySlotIds, SymmetricKeySlotId},
    require,
};
use bitwarden_crypto::{
    CompositeEncryptable, CryptoError, IdentifyKey, KeyStore, KeyStoreContext, OctetStreamBytes,
    PrimitiveEncryptable, generate_random_bytes,
};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    EmptyEmailListError, Send, SendAuthType, SendParseError, SendView, SendViewType,
    send::ItemSendFormat, send_client::SendClient,
};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum CreateSendError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    EmptyEmailList(#[from] EmptyEmailListError),
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    #[error(transparent)]
    SendParse(#[from] SendParseError),
}

/// Request model for creating a new Send.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SendAddRequest {
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
    pub auth: SendAuthType,
}

impl
    CompositeEncryptable<
        KeySlotIds,
        SymmetricKeySlotId,
        bitwarden_api_api::models::SendRequestModel,
    > for SendAddRequest
{
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
    ) -> Result<bitwarden_api_api::models::SendRequestModel, CryptoError> {
        self.encrypt_with_item_format(ctx, key, ItemSendFormat::Legacy)
    }
}

impl SendAddRequest {
    fn encrypt_with_item_format(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
        key: SymmetricKeySlotId,
        item_format: ItemSendFormat,
    ) -> Result<bitwarden_api_api::models::SendRequestModel, CryptoError> {
        // Generate the send key
        let k = generate_random_bytes::<[u8; 16]>().to_vec();

        // Derive the shareable send key for encrypting content
        let send_key = Send::derive_shareable_key(ctx, &k)?;

        let (send_type, file, text, data) =
            self.view_type
                .encrypt_with_item_format(ctx, send_key, item_format)?;

        let (password, emails) = self.auth.auth_data(&k);

        Ok(bitwarden_api_api::models::SendRequestModel {
            r#type: Some(send_type),
            auth_type: Some(self.auth.auth_type().into()),
            file_length: None,
            name: Some(self.name.encrypt(ctx, send_key)?.to_string()),
            notes: self
                .notes
                .as_ref()
                .map(|n| n.encrypt(ctx, send_key))
                .transpose()?
                .map(|e| e.to_string()),
            // Encrypt the send key itself with the user key
            key: OctetStreamBytes::from(k).encrypt(ctx, key)?.to_string(),
            max_access_count: self.max_access_count.map(|c| c as i32),
            expiration_date: self.expiration_date.map(|d| d.to_rfc3339()),
            deletion_date: self.deletion_date.to_rfc3339(),
            file,
            text,
            data,
            password,
            emails,
            disabled: self.disabled,
            hide_email: Some(self.hide_email),
        })
    }
}

impl IdentifyKey<SymmetricKeySlotId> for SendAddRequest {
    fn key_identifier(&self) -> SymmetricKeySlotId {
        SymmetricKeySlotId::User
    }
}

async fn create_send<R: Repository<Send> + ?Sized>(
    key_store: &KeyStore<KeySlotIds>,
    api_client: &bitwarden_api_api::apis::ApiClient,
    repository: &R,
    request: SendAddRequest,
    item_format: ItemSendFormat,
) -> Result<SendView, CreateSendError> {
    request.auth.validate()?;

    let send_request = request.encrypt_with_item_format(
        &mut key_store.context(),
        request.key_identifier(),
        item_format,
    )?;

    let resp = api_client.sends_api().post(Some(send_request)).await?;

    let send: Send = resp.try_into()?;

    repository.set(require!(send.id), send.clone()).await?;

    Ok(key_store.decrypt(&send)?)
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl SendClient {
    /// Create a new [Send] and save it to the server.
    pub async fn create(&self, request: SendAddRequest) -> Result<SendView, CreateSendError> {
        let key_store = self.client.internal.get_key_store();
        let config = self.client.internal.get_api_configurations();
        let repository = self.get_repository()?;

        create_send(
            key_store,
            &config.api_client,
            repository.as_ref(),
            request,
            ItemSendFormat::Legacy,
        )
        .await
    }

    /// Create a new [Send] and save it to the server. An Item Send is stored in the sealed blob
    /// format ([`Send::data_v2`]); [`SendClient::create`] stores it in the [`Send::data`] format.
    ///
    /// Item Sends require `CipherView.id`, and partial (restricted) cipher views are refused.
    pub async fn create_v2(&self, request: SendAddRequest) -> Result<SendView, CreateSendError> {
        let key_store = self.client.internal.get_key_store();
        let config = self.client.internal.get_api_configurations();
        let repository = self.get_repository()?;

        create_send(
            key_store,
            &config.api_client,
            repository.as_ref(),
            request,
            ItemSendFormat::SealedBlob,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{apis::ApiClient, models::SendResponseModel};
    use bitwarden_crypto::SymmetricKeyAlgorithm;
    use bitwarden_test::MemoryRepository;
    use uuid::uuid;

    use super::*;
    use crate::{
        AuthType, SendId, SendTextView, SendType, SendView,
        send::tests::{TEST_ITEM_ID, item_send_cipher_view},
    };

    #[tokio::test]
    async fn test_create_send() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        {
            let mut ctx = store.context_mut();
            let local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(local_key_id, SymmetricKeySlotId::User)
                .unwrap();
        }

        let send_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.sends_api
                .expect_post()
                .returning(move |model| {
                    let model = model.unwrap();
                    Ok(SendResponseModel {
                        id: Some(send_id),
                        name: model.name,
                        revision_date: Some("2025-01-01T00:00:00Z".to_string()),
                        object: Some("send".to_string()),
                        access_id: None,
                        r#type: model.r#type,
                        auth_type: model.auth_type,
                        notes: model.notes,
                        file: model.file,
                        text: model.text,
                        data: model.data,
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

        let repository = MemoryRepository::<Send>::default();

        let result = create_send(
            &store,
            &api_client,
            &repository,
            SendAddRequest {
                name: "test".to_string(),
                notes: Some("notes".to_string()),
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
            ItemSendFormat::Legacy,
        )
        .await
        .unwrap();

        // Verify the result (excluding the generated key which is random)
        assert_eq!(result.id, Some(crate::send::SendId::new(send_id)));
        assert_eq!(result.name, "test");
        assert_eq!(result.notes, Some("notes".to_string()));
        assert!(result.key.is_some(), "Expected a generated key");
        assert_eq!(result.new_password, None);
        assert!(!result.has_password);
        assert_eq!(result.r#type, SendType::Text);
        assert_eq!(result.file, None);
        assert_eq!(
            result.text,
            Some(SendTextView {
                text: Some("test".to_string()),
                hidden: false,
            })
        );
        assert_eq!(result.max_access_count, None);
        assert_eq!(result.access_count, 0);
        assert!(!result.disabled);
        assert!(!result.hide_email);
        assert_eq!(
            result.deletion_date,
            "2025-01-10T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
        assert_eq!(result.expiration_date, None);
        assert_eq!(result.emails, Vec::<String>::new());
        assert_eq!(result.auth_type, AuthType::None);
        assert_eq!(
            result.revision_date,
            "2025-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );

        // Confirm the send was stored in the repository
        assert_eq!(
            store
                .decrypt::<SymmetricKeySlotId, Send, SendView>(
                    &repository.get(SendId::new(send_id)).await.unwrap().unwrap()
                )
                .unwrap(),
            result
        );
    }

    #[tokio::test]
    async fn test_create_send_http_error() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        {
            let mut ctx = store.context_mut();
            let local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(local_key_id, SymmetricKeySlotId::User)
                .unwrap();
        }

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.sends_api
                .expect_post()
                .returning(move |_model| Err(std::io::Error::other("Simulated error").into()));
        });

        let repository = MemoryRepository::<Send>::default();

        let result = create_send(
            &store,
            &api_client,
            &repository,
            SendAddRequest {
                name: "test".to_string(),
                notes: Some("notes".to_string()),
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
            ItemSendFormat::Legacy,
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CreateSendError::Api(_)));
    }

    fn item_add_request() -> SendAddRequest {
        SendAddRequest {
            name: "item".to_string(),
            notes: None,
            view_type: SendViewType::Item(Box::new(crate::send::SendItemView {
                data: item_send_cipher_view(),
            })),
            max_access_count: None,
            disabled: false,
            hide_email: false,
            deletion_date: "2025-01-10T00:00:00Z".parse().unwrap(),
            expiration_date: None,
            auth: SendAuthType::None,
        }
    }

    /// Drives `create_send` with an echoing server and returns the captured request, the
    /// key store and the repository.
    async fn capture_create_post_model(
        request: SendAddRequest,
        item_format: ItemSendFormat,
    ) -> (
        bitwarden_api_api::models::SendRequestModel,
        KeyStore<KeySlotIds>,
        MemoryRepository<Send>,
        SendView,
    ) {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        {
            let mut ctx = store.context_mut();
            let local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(local_key_id, SymmetricKeySlotId::User)
                .unwrap();
        }

        let send_id = uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1");
        let captured: std::sync::Arc<
            std::sync::Mutex<Option<bitwarden_api_api::models::SendRequestModel>>,
        > = std::sync::Arc::new(std::sync::Mutex::new(None));
        let sink = captured.clone();

        let api_client = ApiClient::new_mocked(move |mock| {
            let sink = sink.clone();
            mock.sends_api
                .expect_post()
                .returning(move |model| {
                    let model = model.unwrap();
                    *sink.lock().unwrap() = Some(model.clone());
                    Ok(SendResponseModel {
                        id: Some(send_id),
                        name: model.name,
                        revision_date: Some("2025-01-01T00:00:00Z".to_string()),
                        object: Some("send".to_string()),
                        access_id: None,
                        r#type: model.r#type,
                        auth_type: model.auth_type,
                        notes: model.notes,
                        file: model.file,
                        text: model.text,
                        data: model.data,
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

        let repository = MemoryRepository::<Send>::default();
        let view = create_send(&store, &api_client, &repository, request, item_format)
            .await
            .unwrap();

        let model = captured
            .lock()
            .unwrap()
            .take()
            .expect("POST was not called");
        (model, store, repository, view)
    }

    #[tokio::test]
    async fn test_create_v2_sends_sealed_blob_with_metadata() {
        let (model, store, repository, view) =
            capture_create_post_model(item_add_request(), ItemSendFormat::SealedBlob).await;

        let data = model.data.expect("item data");
        assert_eq!(
            data.encryption_version,
            Some(bitwarden_api_api::models::SendEncryptionType::V1)
        );
        assert_eq!(
            data.metadata.expect("metadata").item_id,
            TEST_ITEM_ID.parse::<uuid::Uuid>().unwrap()
        );
        let blob = data.data.expect("blob");
        assert!(serde_json::from_str::<bitwarden_vault::Cipher>(&blob).is_err());

        assert_eq!(view.data.unwrap().data, item_send_cipher_view());
        let stored = repository.get(view.id.unwrap()).await.unwrap().unwrap();
        assert!(stored.data.is_none());
        assert_eq!(stored.data_v2.as_ref().unwrap().data, blob);
        let decrypted: SendView = store.decrypt(&stored).unwrap();
        assert_eq!(decrypted.data.unwrap().data, item_send_cipher_view());
    }

    #[tokio::test]
    async fn test_create_sends_serialized_cipher_without_metadata() {
        let (model, _store, repository, view) =
            capture_create_post_model(item_add_request(), ItemSendFormat::Legacy).await;

        let data = model.data.expect("item data");
        assert!(data.metadata.is_none());
        let json = serde_json::to_value(&data).unwrap();
        let mut keys: Vec<_> = json.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, ["data", "encryptionVersion"]);
        assert!(serde_json::from_str::<bitwarden_vault::Cipher>(&data.data.unwrap()).is_ok());

        let stored = repository.get(view.id.unwrap()).await.unwrap().unwrap();
        assert!(stored.data.is_some());
        assert!(stored.data_v2.is_none());
    }

    #[tokio::test]
    async fn test_create_v2_requires_item_id() {
        let mut request = item_add_request();
        if let SendViewType::Item(item) = &mut request.view_type {
            item.data.id = None;
        }
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        {
            let mut ctx = store.context_mut();
            let local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(local_key_id, SymmetricKeySlotId::User)
                .unwrap();
        }
        // No request may reach the server.
        let api_client = ApiClient::new_mocked(|_mock| {});
        let repository = MemoryRepository::<Send>::default();

        let result = create_send(
            &store,
            &api_client,
            &repository,
            request,
            ItemSendFormat::SealedBlob,
        )
        .await;

        assert!(matches!(
            result,
            Err(CreateSendError::Crypto(CryptoError::MissingField("id")))
        ));
    }
}

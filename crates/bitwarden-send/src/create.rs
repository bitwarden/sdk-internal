use bitwarden_core::{
    ApiError, MissingFieldError,
    key_management::{KeyIds, SymmetricKeyId},
    require,
};
use bitwarden_crypto::{
    CompositeEncryptable, CryptoError, IdentifyKey, KeyStore, KeyStoreContext, OctetStreamBytes,
    PrimitiveEncryptable, generate_random_bytes,
};
use bitwarden_encoding::B64Url;
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
    AuthType, Send, SendFileView, SendParseError, SendTextView, SendType, SendView,
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
    MissingField(#[from] MissingFieldError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    #[error(transparent)]
    SendParse(#[from] SendParseError),
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SendAddEditRequest {
    pub name: String,
    pub notes: Option<String>,
    pub key: Option<String>,
    pub password: Option<String>,

    pub r#type: SendType,
    pub file: Option<SendFileView>,
    pub text: Option<SendTextView>,

    pub max_access_count: Option<u32>,
    pub disabled: bool,
    pub hide_email: bool,

    pub deletion_date: DateTime<Utc>,
    pub expiration_date: Option<DateTime<Utc>>,

    /// Email addresses for OTP authentication.
    /// **Note**: Mutually exclusive with `new_password`. If both are set,
    /// only password authentication will be used.
    pub emails: Vec<String>,
    pub auth_type: AuthType,
}

impl CompositeEncryptable<KeyIds, SymmetricKeyId, bitwarden_api_api::models::SendRequestModel>
    for SendAddEditRequest
{
    fn encrypt_composite(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
        key: SymmetricKeyId,
    ) -> Result<bitwarden_api_api::models::SendRequestModel, CryptoError> {
        // Generate or decode the send key
        let k = match &self.key {
            // Existing send, decode key
            Some(k) => B64Url::try_from(k.as_str())
                .map_err(|_| CryptoError::InvalidKey)?
                .as_bytes()
                .to_vec(),
            // New send, generate random key
            None => {
                let key = generate_random_bytes::<[u8; 16]>();
                key.to_vec()
            }
        };

        // Derive the shareable send key for encrypting content
        let send_key = Send::derive_shareable_key(ctx, &k)?;

        Ok(bitwarden_api_api::models::SendRequestModel {
            r#type: Some(self.r#type.into()),
            auth_type: Some(self.auth_type.into()),
            file_length: None,
            name: Some(self.name.encrypt(ctx, send_key)?.to_string()),
            notes: self.notes.as_ref().map(|n| n.encrypt(ctx, send_key)).transpose()?.map(|e| e.to_string()),
            // Encrypt the send key itself with the user key
            key: OctetStreamBytes::from(k).encrypt(ctx, key)?.to_string(),
            max_access_count: self.max_access_count.map(|c| c as i32),
            expiration_date: self.expiration_date.map(|d| d.to_rfc3339()),
            deletion_date: self.deletion_date.to_rfc3339(),
            file: self.file.as_ref().map(|f| -> Result<_, CryptoError> {
                Ok(Box::new(bitwarden_api_api::models::SendFileModel {
                    id: f.id.clone(),
                    file_name: Some(f.file_name.encrypt(ctx, send_key)?.to_string()),
                    size: f.size.as_ref().and_then(|s| s.parse::<i64>().ok()),
                    size_name: f.size_name.clone(),
                }))
            }).transpose()?,
            text: self.text.as_ref().map(|t| -> Result<_, CryptoError> {
                Ok(Box::new(bitwarden_api_api::models::SendTextModel {
                    text: t.text.as_ref().map(|txt| txt.encrypt(ctx, send_key)).transpose()?.map(|e| e.to_string()),
                    hidden: Some(t.hidden),
                }))
            }).transpose()?,
            password: self.password.clone(),
            emails: if self.emails.is_empty() {
                None
            } else {
                Some(self.emails.join(","))
            },
            disabled: self.disabled,
            hide_email: Some(self.hide_email),
        })
    }
}

impl IdentifyKey<SymmetricKeyId> for SendAddEditRequest {
    fn key_identifier(&self) -> SymmetricKeyId {
        SymmetricKeyId::User
    }
}

pub(super) async fn create_send<R: Repository<Send> + ?Sized>(
    key_store: &KeyStore<KeyIds>,
    api_client: &bitwarden_api_api::apis::ApiClient,
    repository: &R,
    request: SendAddEditRequest,
) -> Result<SendView, CreateSendError> {
    let send_request = key_store.encrypt(request)?;

    let resp = api_client
        .sends_api()
        .post(Some(send_request))
        .await
        .map_err(ApiError::from)?;

    let send: Send = resp.try_into()?;

    repository
        .set(require!(send.id).to_string(), send.clone())
        .await?;

    Ok(key_store.decrypt(&send)?)
}
#[cfg(test)]
mod tests {
    use bitwarden_api_api::{apis::ApiClient, models::SendResponseModel};
    use bitwarden_crypto::SymmetricKeyAlgorithm;
    use bitwarden_test::MemoryRepository;
    use uuid::uuid;

    use super::*;

    #[tokio::test]
    async fn test_create_send() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        {
            let mut ctx = store.context_mut();
            let local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(local_key_id, SymmetricKeyId::User)
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
            SendAddEditRequest {
                name: "test".to_string(),
                notes: Some("notes".to_string()),
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
        .await
        .unwrap();

        // Verify the result (excluding the generated key which is random)
        assert_eq!(result.id, Some(send_id));
        assert_eq!(result.name, "test");
        assert_eq!(result.notes, Some("notes".to_string()));
        assert!(result.key.is_some(), "Expected a generated key");
        assert_eq!(result.new_password, None);
        assert_eq!(result.has_password, false);
        assert_eq!(result.r#type, SendType::Text);
        assert_eq!(result.file, None);
        assert_eq!(result.text, Some(SendTextView {
            text: Some("test".to_string()),
            hidden: false,
        }));
        assert_eq!(result.max_access_count, None);
        assert_eq!(result.access_count, 0);
        assert_eq!(result.disabled, false);
        assert_eq!(result.hide_email, false);
        assert_eq!(result.deletion_date, "2025-01-10T00:00:00Z".parse::<DateTime<Utc>>().unwrap());
        assert_eq!(result.expiration_date, None);
        assert_eq!(result.emails, Vec::<String>::new());
        assert_eq!(result.auth_type, AuthType::None);
        assert_eq!(result.revision_date, "2025-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap());

        // Confirm the send was stored in the repository
        assert_eq!(
            store
                .decrypt::<SymmetricKeyId, Send, SendView>(&repository.get(send_id.to_string()).await.unwrap().unwrap())
                .unwrap(),
            result
        );
    }

    #[tokio::test]
    async fn test_create_send_http_error() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        {
            let mut ctx = store.context_mut();
            let local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(local_key_id, SymmetricKeyId::User)
                .unwrap();
        }

        let api_client = ApiClient::new_mocked(move |mock| {
            mock.sends_api.expect_post().returning(move |_model| {
                Err(bitwarden_api_api::apis::Error::Io(std::io::Error::other(
                    "Simulated error",
                )))
            });
        });

        let repository = MemoryRepository::<Send>::default();

        let result = create_send(
            &store,
            &api_client,
            &repository,
            SendAddEditRequest {
                name: "test".to_string(),
                notes: Some("notes".to_string()),
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
        assert!(matches!(result.unwrap_err(), CreateSendError::Api(_)));
    }
}

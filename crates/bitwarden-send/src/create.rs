use bitwarden_core::{
    ApiError, MissingFieldError,
    key_management::{KeyIds, SymmetricKeyId},
    require,
};
use bitwarden_crypto::{
    CompositeEncryptable, CryptoError, IdentifyKey, KeyStore, KeyStoreContext, PrimitiveEncryptable,
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
    AuthType, Send, SendParseError, SendType, SendView,
    send::{SendFile, SendText},
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
    pub notes: String,
    pub key: String,
    pub password: Option<String>,

    pub r#type: SendType,
    pub file: Option<SendFile>,
    pub text: Option<SendText>,

    pub max_access_count: Option<u32>,
    pub disabled: bool,
    pub hide_email: bool,

    pub deletion_date: DateTime<Utc>,
    pub expiration_date: Option<DateTime<Utc>>,

    /// Email addresses for OTP authentication.
    /// **Note**: Mutually exclusive with `new_password`. If both are set,
    /// only password authentication will be used.
    pub emails: Option<String>,
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
        Ok(bitwarden_api_api::models::SendRequestModel {
            r#type: Some(self.r#type.into()),
            auth_type: Some(self.auth_type.into()),
            file_length: None,
            name: Some(self.name.encrypt(ctx, key)?.to_string()),
            notes: Some(self.notes.encrypt(ctx, key)?.to_string()),
            key: self.key.clone(),
            max_access_count: self.max_access_count.map(|c| c as i32),
            expiration_date: self.expiration_date.map(|d| d.to_rfc3339()),
            deletion_date: self.deletion_date.to_rfc3339(),
            file: self.file.as_ref().map(|f| {
                Box::new(bitwarden_api_api::models::SendFileModel {
                    id: f.id.clone(),
                    file_name: Some(f.file_name.to_string()),
                    size: f.size.as_ref().and_then(|s| s.parse::<i64>().ok()),
                    size_name: f.size_name.clone(),
                })
            }),
            text: self.text.as_ref().map(|t| {
                Box::new(bitwarden_api_api::models::SendTextModel {
                    text: t.text.as_ref().map(|txt| txt.to_string()),
                    hidden: Some(t.hidden),
                })
            }),
            password: self.password.clone(),
            emails: self.emails.clone(),
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
    #[tokio::test]
    async fn test_create_send() {}

    #[tokio::test]
    async fn test_create_send_http_error() {}
}

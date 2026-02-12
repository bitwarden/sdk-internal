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

    // Verify the folder we're updating exists
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

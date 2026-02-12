use bitwarden_core::key_management::KeyIds;
use bitwarden_crypto::{CryptoError, KeyStore};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError};
use thiserror::Error;
use uuid::Uuid;

use crate::{Send, SendView, error::ItemNotFoundError};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum GetSendError {
    #[error(transparent)]
    ItemNotFound(#[from] ItemNotFoundError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

pub(super) async fn get_send(
    store: &KeyStore<KeyIds>,
    repository: &dyn Repository<Send>,
    id: Uuid,
) -> Result<SendView, GetSendError> {
    let send = repository
        .get(id.to_string())
        .await?
        .ok_or(ItemNotFoundError)?;

    Ok(store.decrypt(&send)?)
}

pub(super) async fn list_folders(
    store: &KeyStore<KeyIds>,
    repository: &dyn Repository<Send>,
) -> Result<Vec<SendView>, GetSendError> {
    let sends = repository.list().await?;
    let views = store.decrypt_list(&sends)?;
    Ok(views)
}

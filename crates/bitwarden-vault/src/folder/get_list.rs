use bitwarden_core::key_management::KeyIds;
use bitwarden_crypto::{CryptoError, KeyStore};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError};
use thiserror::Error;

use crate::{Folder, FolderView, ItemNotFoundError};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum GetFolderError {
    #[error(transparent)]
    ItemNotFound(#[from] ItemNotFoundError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    RepositoryError(#[from] RepositoryError),
}

pub(super) async fn get_folder(
    store: &KeyStore<KeyIds>,
    repository: &dyn Repository<Folder>,
    id: &str,
) -> Result<FolderView, GetFolderError> {
    let folder = repository
        .get(id.to_string())
        .await?
        .ok_or(ItemNotFoundError)?;

    Ok(store.decrypt(&folder)?)
}

pub(super) async fn list_folders(
    store: &KeyStore<KeyIds>,
    repository: &dyn Repository<Folder>,
) -> Result<Vec<FolderView>, GetFolderError> {
    let folders = repository.list().await?;
    let views = store.decrypt_list(&folders)?;
    Ok(views)
}

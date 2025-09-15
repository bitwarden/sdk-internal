use bitwarden_core::key_management::KeyIds;
use bitwarden_crypto::{CryptoError, KeyStore};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError};
use thiserror::Error;

use crate::{Cipher, CipherView, ItemNotFoundError};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum GetCipherError {
    #[error(transparent)]
    ItemNotFound(#[from] ItemNotFoundError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    RepositoryError(#[from] RepositoryError),
}

pub(super) async fn get_cipher(
    store: &KeyStore<KeyIds>,
    repository: &dyn Repository<Cipher>,
    id: &str,
) -> Result<CipherView, GetCipherError> {
    let cipher = repository
        .get(id.to_string())
        .await?
        .ok_or(ItemNotFoundError)?;

    Ok(store.decrypt(&cipher)?)
}

pub(super) async fn list_ciphers(
    store: &KeyStore<KeyIds>,
    repository: &dyn Repository<Cipher>,
) -> Result<Vec<CipherView>, GetCipherError> {
    let ciphers = repository.list().await?;
    let views = store.decrypt_list(&ciphers)?;
    Ok(views)
}

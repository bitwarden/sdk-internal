use bitwarden_core::key_management::KeyIds;
use bitwarden_crypto::{CryptoError, KeyStore};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError};
use thiserror::Error;
use wasm_bindgen::prelude::wasm_bindgen;

use super::CiphersClient;
use crate::{Cipher, CipherView, ItemNotFoundError, cipher::cipher::DecryptCipherListResult};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum GetCipherError {
    #[error(transparent)]
    ItemNotFound(#[from] ItemNotFoundError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

async fn get_cipher(
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

async fn list_ciphers(
    store: &KeyStore<KeyIds>,
    repository: &dyn Repository<Cipher>,
) -> Result<DecryptCipherListResult, GetCipherError> {
    let ciphers = repository.list().await?;
    let (successes, failures) = store.decrypt_list_with_failures(&ciphers);
    Ok(DecryptCipherListResult {
        successes,
        failures: failures.into_iter().cloned().collect(),
    })
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CiphersClient {
    /// Get all ciphers from state and decrypt them, returning both successes and failures.
    /// This method will not fail when some ciphers fail to decrypt, allowing for graceful
    /// handling of corrupted or problematic cipher data.
    pub async fn list(&self) -> Result<DecryptCipherListResult, GetCipherError> {
        let key_store = self.client.internal.get_key_store();
        let repository = self.get_repository()?;

        list_ciphers(key_store, repository.as_ref()).await
    }

    /// Get [Cipher] by ID from state and decrypt it to a [CipherView].
    pub async fn get(&self, cipher_id: &str) -> Result<CipherView, GetCipherError> {
        let key_store = self.client.internal.get_key_store();
        let repository = self.get_repository()?;

        get_cipher(key_store, repository.as_ref(), cipher_id).await
    }
}

use bitwarden_core::key_management::KeySlotIds;
use bitwarden_crypto::{CryptoError, KeyStore};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use super::CiphersClient;
use crate::{
    Cipher, CipherView, ItemNotFoundError,
    cipher::cipher::{BlobAwareDecrypt, DecryptCipherListResult, DecryptCipherResult},
};

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
    store: &KeyStore<KeySlotIds>,
    repository: &dyn Repository<Cipher>,
    id: &str,
    use_strict_decryption: bool,
) -> Result<CipherView, GetCipherError> {
    let id = id.parse().map_err(|_| ItemNotFoundError)?;
    let cipher = repository.get(id).await?.ok_or(ItemNotFoundError)?;

    Ok(store.decrypt(&BlobAwareDecrypt {
        inner: cipher,
        use_strict: use_strict_decryption,
    })?)
}

fn wrap_for_decrypt(
    ciphers: Vec<Cipher>,
    use_strict_decryption: bool,
) -> Vec<BlobAwareDecrypt<Cipher>> {
    ciphers
        .into_iter()
        .map(|inner| BlobAwareDecrypt {
            inner,
            use_strict: use_strict_decryption,
        })
        .collect()
}

async fn list_ciphers(
    store: &KeyStore<KeySlotIds>,
    repository: &dyn Repository<Cipher>,
    use_strict_decryption: bool,
) -> Result<DecryptCipherListResult, GetCipherError> {
    let ciphers = repository.list().await?;
    let wrapped = wrap_for_decrypt(ciphers, use_strict_decryption);
    let (successes, failures) = store.decrypt_list_with_failures(&wrapped);
    Ok(DecryptCipherListResult {
        successes,
        failures: failures.into_iter().map(|f| f.inner.clone()).collect(),
    })
}

async fn get_all_ciphers(
    store: &KeyStore<KeySlotIds>,
    repository: &dyn Repository<Cipher>,
    use_strict_decryption: bool,
) -> Result<DecryptCipherResult, GetCipherError> {
    let ciphers = repository.list().await?;
    let wrapped = wrap_for_decrypt(ciphers, use_strict_decryption);
    let (successes, failures) = store.decrypt_list_with_failures(&wrapped);
    Ok(DecryptCipherResult {
        successes,
        failures: failures.into_iter().map(|f| f.inner.clone()).collect(),
    })
}

#[allow(deprecated)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CiphersClient {
    /// Get all ciphers from state and decrypt them to [crate::CipherListView], returning both
    /// successes and failures. This method will not fail when some ciphers fail to decrypt,
    /// allowing for graceful handling of corrupted or problematic cipher data.
    pub async fn list(&self) -> Result<DecryptCipherListResult, GetCipherError> {
        let key_store = self.client.internal.get_key_store();
        let repository = self.get_repository()?;

        list_ciphers(
            key_store,
            repository.as_ref(),
            self.is_strict_decrypt().await,
        )
        .await
    }

    /// Get all ciphers from state and decrypt them to full [CipherView], returning both
    /// successes and failures. This method will not fail when some ciphers fail to decrypt,
    /// allowing for graceful handling of corrupted or problematic cipher data.
    pub async fn get_all(&self) -> Result<DecryptCipherResult, GetCipherError> {
        let key_store = self.client.internal.get_key_store();
        let repository = self.get_repository()?;

        get_all_ciphers(
            key_store,
            repository.as_ref(),
            self.is_strict_decrypt().await,
        )
        .await
    }

    /// Get [Cipher] by ID from state and decrypt it to a [CipherView].
    pub async fn get(&self, cipher_id: &str) -> Result<CipherView, GetCipherError> {
        let key_store = self.client.internal.get_key_store();
        let repository = self.get_repository()?;

        get_cipher(
            key_store,
            repository.as_ref(),
            cipher_id,
            self.is_strict_decrypt().await,
        )
        .await
    }
}

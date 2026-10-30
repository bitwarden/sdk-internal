use bitwarden_core::key_management::KeySlotIds;
use bitwarden_crypto::{CryptoError, KeyStore};
use bitwarden_error::bitwarden_error;
#[cfg(feature = "wasm")]
use bitwarden_ffi::BwStream;
use bitwarden_state::repository::{Repository, RepositoryError};
use futures::Stream;
use thiserror::Error;

use super::{
    CiphersClient,
    list_stream::{DecryptStreamError, DecryptedChunk, decrypted_list_stream},
};
#[cfg(feature = "wasm")]
use crate::CipherListView;
use crate::{
    Cipher, CipherId, CipherView, ItemNotFoundError,
    cipher::cipher::{DecryptCipherListResult, DecryptCipherResult, StrictDecrypt},
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
    id: CipherId,
    use_strict_decryption: bool,
) -> Result<CipherView, GetCipherError> {
    let cipher = repository.get(id).await?.ok_or(ItemNotFoundError)?;

    Ok(if use_strict_decryption {
        store.decrypt(&StrictDecrypt(cipher))?
    } else {
        store.decrypt(&cipher)?
    })
}

async fn list_ciphers(
    store: &KeyStore<KeySlotIds>,
    repository: &dyn Repository<Cipher>,
    use_strict_decryption: bool,
) -> Result<DecryptCipherListResult, GetCipherError> {
    let ciphers = repository.list().await?;
    Ok(if use_strict_decryption {
        let wrapped: Vec<StrictDecrypt<Cipher>> = ciphers.into_iter().map(StrictDecrypt).collect();
        let (successes, failures) = store.decrypt_list_with_failures(&wrapped);
        DecryptCipherListResult {
            successes,
            failures: failures.into_iter().map(|f| f.0.clone()).collect(),
        }
    } else {
        let (successes, failures) = store.decrypt_list_with_failures(&ciphers);
        DecryptCipherListResult {
            successes,
            failures: failures.into_iter().cloned().collect(),
        }
    })
}

async fn get_all_ciphers(
    store: &KeyStore<KeySlotIds>,
    repository: &dyn Repository<Cipher>,
    use_strict_decryption: bool,
) -> Result<DecryptCipherResult, GetCipherError> {
    let ciphers = repository.list().await?;
    Ok(if use_strict_decryption {
        let wrapped: Vec<StrictDecrypt<Cipher>> = ciphers.into_iter().map(StrictDecrypt).collect();
        let (successes, failures) = store.decrypt_list_with_failures(&wrapped);
        DecryptCipherResult {
            successes,
            failures: failures.into_iter().map(|f| f.0.clone()).collect(),
        }
    } else {
        let (successes, failures) = store.decrypt_list_with_failures(&ciphers);
        DecryptCipherResult {
            successes,
            failures: failures.into_iter().cloned().collect(),
        }
    })
}

/// How many ciphers [`CiphersClient::list_iterable`] reads and decrypts at a time by default.
#[cfg(feature = "wasm")]
const LIST_CHUNK_SIZE: usize = 250;

#[allow(deprecated)]
#[bitwarden_ffi::wasm_export]
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

    /// Get all ciphers from state and decrypt them to [crate::CipherListView] `chunk_size` at a
    /// time (250 when not given, at least one), as an `AsyncIterable` in the repository's order.
    ///
    /// Each cipher arrives as `{ ok: true, value }` with its view, or as `{ ok: false, error }`
    /// with the encrypted cipher when it fails to decrypt. A failure of the listing itself ends
    /// the iteration: the iterator's `next()` rejects once with a [`DecryptStreamError`], and later
    /// calls return done. That happens when the repository fails to read, and when the vault is
    /// locked when a chunk is decrypted. Breaking out of a `for await` stops reading.
    ///
    /// With a repository that reads lazily, WASM memory holds one chunk at a time; see
    /// [`Repository::stream`].
    #[cfg(feature = "wasm")]
    pub fn list_iterable(
        &self,
        chunk_size: Option<u32>,
    ) -> BwStream<Result<CipherListView, Box<Cipher>>> {
        let chunk_size = chunk_size.map_or(LIST_CHUNK_SIZE, |size| size as usize);
        BwStream::from_results(self.list_stream(chunk_size))
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
    pub async fn get(&self, cipher_id: CipherId) -> Result<CipherView, GetCipherError> {
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

#[allow(deprecated)]
impl CiphersClient {
    /// Get all ciphers from state and decrypt them to [crate::CipherListView] in chunks of up to
    /// `chunk_size` (at least one), in the repository's order.
    ///
    /// A cipher that fails to decrypt is its chunk's `Err` item. A failure of the listing itself
    /// ends the stream with one `Err`: the repository failing to read, or the vault being locked
    /// when a chunk is decrypted. With a repository that reads lazily, memory holds one chunk at a
    /// time; see [`Repository::stream`].
    pub fn list_stream(
        &self,
        chunk_size: usize,
    ) -> impl Stream<Item = Result<DecryptedChunk, DecryptStreamError>> + Send + 'static {
        decrypted_list_stream(
            self.get_repository(),
            self.key_store.clone(),
            self.client.clone(),
            chunk_size,
        )
    }
}

use bitwarden_core::key_management::KeySlotIds;
use bitwarden_crypto::{CryptoError, KeyStore};
use bitwarden_error::bitwarden_error;
#[cfg(feature = "wasm")]
use bitwarden_ffi::BwStream;
use bitwarden_state::repository::{Repository, RepositoryError, RepositoryOption};
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

/// How many ciphers [`CiphersClient::list_stream`] reads and decrypts at a time.
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

    /// Get all ciphers from state and decrypt them to [crate::CipherListView] a chunk at a time,
    /// as an `AsyncIterable` in the repository's order.
    ///
    /// Each cipher arrives as `{ ok: true, value }` with its view, or as `{ ok: false, error }`
    /// with the encrypted cipher when it fails to decrypt, as [`Self::list`] decrypts it. The
    /// repository failing to read ends the iteration: the iterator's `next()` rejects once with a
    /// [`DecryptStreamError`], and later calls return done. Breaking out of a `for await` stops
    /// reading.
    ///
    /// With a repository that reads lazily, WASM memory holds one chunk at a time; see
    /// [`Repository::stream`].
    #[cfg(feature = "wasm")]
    pub fn list_iterable(&self) -> BwStream<Result<CipherListView, Box<Cipher>>> {
        BwStream::from_results(self.list_stream())
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

impl CiphersClient {
    /// Get all ciphers from state and decrypt them to [crate::CipherListView] in chunks of up to
    /// 250, in the repository's order.
    ///
    /// A cipher that fails to decrypt is its chunk's `Err` item. The repository failing to read
    /// ends the stream with one `Err`. With a repository that reads lazily, memory holds one chunk
    /// at a time; see [`Repository::stream`].
    pub fn list_stream(
        &self,
    ) -> impl Stream<Item = Result<DecryptedChunk, DecryptStreamError>> + Send + 'static {
        #[allow(deprecated)]
        let client = self.client.clone();
        decrypted_list_stream(
            self.repository.require().cloned(),
            self.key_store.clone(),
            client,
            LIST_CHUNK_SIZE,
        )
    }
}

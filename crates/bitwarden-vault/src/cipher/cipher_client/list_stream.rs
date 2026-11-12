//! Lists and decrypts the ciphers in state a chunk at a time.
//!
//! WASM linear memory grows to the largest single call and never shrinks. Decrypting a whole vault
//! in one call holds every encrypted and decrypted cipher at once, and that peak stays reserved for
//! the rest of the session. [`decrypted_list_stream`] reads the cipher repository with
//! [`Repository::stream`] and decrypts each chunk as it arrives, so memory only holds the chunk
//! being decrypted when the repository reads lazily.

use std::sync::Arc;

use bitwarden_core::{
    Client,
    key_management::{KeySlotIds, SymmetricKeySlotId},
};
use bitwarden_crypto::{Decryptable, IdentifyKey, KeyStore};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError};
use futures::{Stream, StreamExt, stream};
use thiserror::Error;

use crate::{Cipher, CipherListView, cipher::cipher::StrictDecrypt};

/// Ends a cipher stream, as opposed to a single cipher that fails to decrypt.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum DecryptStreamError {
    /// The user key is not in the key store, so no cipher can decrypt.
    #[error("The vault is locked")]
    VaultLocked,
    /// The ciphers could not be read from state.
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

/// One chunk of decrypted ciphers: each cipher's view, or the cipher itself when it fails to
/// decrypt, in the repository's order. A [`Cipher`] is over ten times the size of a
/// [`CipherListView`], so a failed one is boxed to keep the chunk small.
pub type DecryptedChunk = Vec<Result<CipherListView, Box<Cipher>>>;

/// A cipher that failed to decrypt crosses to JavaScript as the plain `Cipher`.
#[cfg(feature = "wasm")]
impl From<Box<Cipher>> for wasm_bindgen::JsValue {
    fn from(cipher: Box<Cipher>) -> Self {
        (*cipher).into()
    }
}

/// Reads the ciphers from `repository` in chunks of up to `chunk_size` (at least one) and
/// decrypts each chunk as it arrives.
///
/// A cipher that fails to decrypt is its chunk's `Err` item and the stream goes on. A problem with
/// the stream itself ends it with one `Err`: the repository failing to read, or the vault being
/// locked when a chunk is decrypted. Strict decryption is decided by `client`'s feature flags
/// when the stream is first polled.
pub(crate) fn decrypted_list_stream(
    repository: Result<Arc<dyn Repository<Cipher>>, RepositoryError>,
    key_store: KeyStore<KeySlotIds>,
    client: Client,
    chunk_size: usize,
) -> impl Stream<Item = Result<DecryptedChunk, DecryptStreamError>> + Send + 'static {
    let start = async move {
        let repository = repository?;
        let decryptor = Decryptor::new(key_store, &client).await;
        Ok::<_, DecryptStreamError>((repository.stream(chunk_size), decryptor))
    };
    stream::once(start).flat_map(|started| match started {
        Ok(state) => stream::unfold(Some(state), |state| async move {
            let (mut chunks, decryptor) = state?;
            let decrypted = chunks
                .next()
                .await?
                .map_err(DecryptStreamError::from)
                .and_then(|chunk| decryptor.decrypt(chunk));
            match decrypted {
                Ok(results) => Some((Ok(results), Some((chunks, decryptor)))),
                Err(error) => Some((Err(error), None)),
            }
        })
        .boxed(),
        Err(error) => stream::iter([Err(error)]).boxed(),
    })
}

/// Decrypts chunks of ciphers with the same key store path as
/// [`CiphersClient::decrypt_list_with_failures`](super::CiphersClient::decrypt_list_with_failures),
/// keeping each result in its cipher's position.
struct Decryptor {
    key_store: KeyStore<KeySlotIds>,
    strict: bool,
}

impl Decryptor {
    /// Reads whether to decrypt strictly from `client`'s feature flags.
    async fn new(key_store: KeyStore<KeySlotIds>, client: &Client) -> Self {
        Self {
            key_store,
            strict: client.flags().get().await.strict_cipher_decryption,
        }
    }

    /// Decrypts `ciphers` in order, returning each cipher that fails in its place.
    ///
    /// A missing user key fails the whole chunk with [`DecryptStreamError::VaultLocked`]: no
    /// cipher can decrypt then, and a locked vault is not a problem with any one cipher. Any other
    /// failure, such as a cipher key that cannot be unwrapped, is that cipher's.
    fn decrypt(&self, ciphers: Vec<Cipher>) -> Result<DecryptedChunk, DecryptStreamError> {
        if self.strict {
            let wrapped: Vec<StrictDecrypt<Cipher>> =
                ciphers.into_iter().map(StrictDecrypt).collect();
            self.decrypt_each(&wrapped, |strict| &strict.0)
        } else {
            self.decrypt_each(&ciphers, |cipher| cipher)
        }
    }

    /// Decrypts `items` by reference and clones only the ciphers that fail: moving each
    /// [`Cipher`], over 5 KB, out of the chunk measured about 70% more linear memory per chunk.
    fn decrypt_each<D>(
        &self,
        items: &[D],
        cipher: impl Fn(&D) -> &Cipher,
    ) -> Result<DecryptedChunk, DecryptStreamError>
    where
        D: Decryptable<KeySlotIds, SymmetricKeySlotId, CipherListView>
            + IdentifyKey<SymmetricKeySlotId>,
    {
        let mut ctx = self.key_store.context();
        if !ctx.has_symmetric_key(SymmetricKeySlotId::User) {
            return Err(DecryptStreamError::VaultLocked);
        }

        Ok(items
            .iter()
            .map(|item| {
                let result = item.decrypt(&mut ctx, item.key_identifier());
                ctx.clear_local();
                result.map_err(|_| Box::new(cipher(item).clone()))
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::client::test_accounts::test_bitwarden_com_account;
    use bitwarden_test::MemoryRepository;

    use super::{super::tests::test_cipher, *};
    use crate::{CipherId, VaultClientExt};

    async fn decryptor() -> (Client, Decryptor) {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        let key_store = client.vault().ciphers().key_store.clone();
        (
            client,
            Decryptor {
                key_store,
                strict: false,
            },
        )
    }

    async fn strict_decryptor() -> (Client, Decryptor) {
        let (client, decryptor) = decryptor().await;
        (
            client,
            Decryptor {
                strict: true,
                ..decryptor
            },
        )
    }

    /// A cipher whose key is wrapped with an organization key the store does not hold, so the
    /// cipher key cannot be unwrapped. A missing key for a single field only blanks that field.
    fn cipher_of_unknown_organization() -> Cipher {
        Cipher {
            id: Some("9b1e1d8c-0000-4000-8000-000000000002".parse().unwrap()),
            organization_id: Some("9b1e1d8c-0000-4000-8000-000000000001".parse().unwrap()),
            key: Some("2.6TPEiYULFg/4+3CpDRwCqw==|6swweBHCJcd5CHdwBBWuRN33XRV22VoroDFDUmiM4OzjPEAhgZK57IZS1KkBlCcFvT+t+YbsmDcdv+Lqr+iJ3MmzfJ40MCB5TfYy+22HVRA=|rkgFDh2IWTfPC1Y66h68Diiab/deyi1p/X0Fwkva0NQ=".parse().unwrap()),
            ..test_cipher()
        }
    }

    /// `test_cipher` under the id `n`.
    fn numbered_cipher(n: u32) -> Cipher {
        Cipher {
            id: Some(CipherId::new(uuid::Uuid::from_u128(u128::from(n)))),
            ..test_cipher()
        }
    }

    /// A repository holding `ciphers`, as the client's cipher state.
    async fn repository_of(ciphers: Vec<Cipher>) -> Arc<dyn Repository<Cipher>> {
        let repository = Arc::new(MemoryRepository::<Cipher>::default());
        repository
            .set_bulk(
                ciphers
                    .into_iter()
                    .map(|cipher| (cipher.id.expect("test ciphers have ids"), cipher))
                    .collect(),
            )
            .await
            .unwrap();
        repository
    }

    #[tokio::test]
    async fn keeps_each_failure_in_its_place() {
        let (_client, decryptor) = decryptor().await;
        let bad = cipher_of_unknown_organization();

        let results = decryptor
            .decrypt(vec![test_cipher(), bad.clone(), test_cipher()])
            .unwrap();

        assert_eq!(results.len(), 3);
        assert_eq!(results[0].as_ref().unwrap().name, "234234");
        assert_eq!(results[1].as_ref().unwrap_err().id, bad.id);
        assert_eq!(results[2].as_ref().unwrap().name, "234234");
    }

    #[tokio::test]
    async fn keeps_each_failure_in_its_place_when_strict() {
        let (_client, decryptor) = strict_decryptor().await;
        let bad = cipher_of_unknown_organization();

        let results = decryptor.decrypt(vec![bad.clone(), test_cipher()]).unwrap();

        assert_eq!(results[0].as_ref().unwrap_err().id, bad.id);
        assert_eq!(results[1].as_ref().unwrap().name, "234234");
    }

    #[tokio::test]
    async fn fails_the_whole_chunk_when_the_vault_is_locked() {
        let (_client, decryptor) = decryptor().await;
        decryptor.key_store.clear();

        let result = decryptor.decrypt(vec![test_cipher()]);

        assert!(matches!(result, Err(DecryptStreamError::VaultLocked)));
    }

    #[tokio::test]
    async fn decrypts_an_empty_chunk_to_nothing() {
        let (_client, decryptor) = decryptor().await;

        assert!(decryptor.decrypt(Vec::new()).unwrap().is_empty());
    }

    #[tokio::test]
    async fn streams_every_cipher_in_chunks() {
        let (client, decryptor) = decryptor().await;
        let ciphers: Vec<Cipher> = (1..=5).map(numbered_cipher).collect();
        let repository = repository_of(ciphers.clone()).await;

        let chunks: Vec<_> = decrypted_list_stream(Ok(repository), decryptor.key_store, client, 2)
            .collect()
            .await;

        let sizes: Vec<usize> = chunks.iter().map(|c| c.as_ref().unwrap().len()).collect();
        assert_eq!(sizes, vec![2, 2, 1]);
        let mut ids: Vec<_> = chunks
            .into_iter()
            .flat_map(|chunk| chunk.unwrap())
            .map(|item| item.unwrap().id)
            .collect();
        ids.sort();
        assert_eq!(ids, ciphers.iter().map(|c| c.id).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn streams_nothing_from_an_empty_repository() {
        let (client, decryptor) = decryptor().await;
        let repository = repository_of(Vec::new()).await;

        let chunks: Vec<_> = decrypted_list_stream(Ok(repository), decryptor.key_store, client, 2)
            .collect()
            .await;

        assert!(chunks.is_empty());
    }

    #[tokio::test]
    async fn ends_with_vault_locked_when_locked() {
        let (client, decryptor) = decryptor().await;
        let repository = repository_of((1..=3).map(numbered_cipher).collect()).await;
        decryptor.key_store.clear();

        let chunks: Vec<_> = decrypted_list_stream(Ok(repository), decryptor.key_store, client, 2)
            .collect()
            .await;

        assert_eq!(chunks.len(), 1);
        assert!(matches!(chunks[0], Err(DecryptStreamError::VaultLocked)));
    }

    #[tokio::test]
    async fn ends_with_the_repository_error_when_there_is_no_repository() {
        let (client, decryptor) = decryptor().await;
        let missing = Err(RepositoryError::Internal("no cipher repository".to_owned()));

        let chunks: Vec<_> = decrypted_list_stream(missing, decryptor.key_store, client, 2)
            .collect()
            .await;

        assert_eq!(chunks.len(), 1);
        assert!(matches!(chunks[0], Err(DecryptStreamError::Repository(_))));
    }
}

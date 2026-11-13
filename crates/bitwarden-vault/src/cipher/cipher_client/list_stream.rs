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
use bitwarden_crypto::{CryptoError, KeyStore};
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{Repository, RepositoryError, RepositoryStream};
use futures::{Stream, StreamExt, TryStreamExt, future::Either, stream};
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
/// decrypts each chunk as it arrives, with [`KeyStore::decrypt_stream`].
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
    stream::once(async move {
        let repository = repository?;
        let strict = client.flags().get().await.strict_cipher_decryption;
        let chunks = unlocked_chunks(repository.stream(chunk_size), key_store.clone());
        let decrypted = if strict {
            let chunks =
                chunks.map_ok(|ciphers| ciphers.into_iter().map(StrictDecrypt).collect::<Vec<_>>());
            Either::Left(
                key_store
                    .decrypt_stream(chunks)
                    .map_ok(|results| into_chunk(results, |StrictDecrypt(cipher)| cipher)),
            )
        } else {
            Either::Right(
                key_store
                    .decrypt_stream(chunks)
                    .map_ok(|results| into_chunk(results, |cipher| cipher)),
            )
        };
        Ok::<_, DecryptStreamError>(decrypted)
    })
    .try_flatten()
}

/// Passes on each chunk of `chunks` while the user key is in `key_store`, and
/// [`DecryptStreamError::VaultLocked`] in place of a chunk read when it is not: no cipher can
/// decrypt then, and a locked vault is not a problem with any one cipher.
fn unlocked_chunks(
    chunks: RepositoryStream<Cipher>,
    key_store: KeyStore<KeySlotIds>,
) -> impl Stream<Item = Result<Vec<Cipher>, DecryptStreamError>> + Send + 'static {
    chunks.map(move |chunk| {
        let ciphers = chunk?;
        // The context holds the store's read lock until the end of the condition, so the lock is
        // released before the chunk is decrypted.
        if key_store
            .context()
            .has_symmetric_key(SymmetricKeySlotId::User)
        {
            Ok(ciphers)
        } else {
            Err(DecryptStreamError::VaultLocked)
        }
    })
}

/// Turns a chunk of [`KeyStore::decrypt_stream`] results into a [`DecryptedChunk`]: each failure
/// stays in its place as the cipher alone, which `cipher` takes out of the decrypted item.
fn into_chunk<D>(
    results: Vec<Result<CipherListView, Box<(D, CryptoError)>>>,
    cipher: fn(D) -> Cipher,
) -> DecryptedChunk {
    results
        .into_iter()
        .map(|result| {
            result.map_err(|failure| {
                let (item, _) = *failure;
                Box::new(cipher(item))
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use bitwarden_core::{
        client::test_accounts::test_bitwarden_com_account,
        key_management::create_test_crypto_with_user_key,
    };
    use bitwarden_crypto::{PrimitiveEncryptable, SymmetricCryptoKey, SymmetricKeyAlgorithm};
    use bitwarden_test::MemoryRepository;

    use super::{super::tests::test_cipher, *};
    use crate::{CipherId, VaultClientExt};

    /// A client unlocked with the test account, and its key store.
    async fn unlocked_client() -> (Client, KeyStore<KeySlotIds>) {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        let key_store = client.vault().ciphers().key_store.clone();
        (client, key_store)
    }

    /// [`unlocked_client`] with the strict cipher decryption feature flag on.
    async fn strict_client() -> (Client, KeyStore<KeySlotIds>) {
        let (client, key_store) = unlocked_client().await;
        client
            .flags()
            .load(HashMap::from([(
                "pm-34500-strict-cipher-decryption".to_owned(),
                true,
            )]))
            .await;
        (client, key_store)
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

    /// `test_cipher` under the id `n`, with its name encrypted under a key the store does not
    /// hold: strict decryption fails the cipher, and lenient decryption blanks the name.
    fn cipher_with_undecryptable_name(n: u32) -> Cipher {
        let other_store = create_test_crypto_with_user_key(SymmetricCryptoKey::make(
            SymmetricKeyAlgorithm::Aes256CbcHmac,
        ));
        let name = "name"
            .to_owned()
            .encrypt(&mut other_store.context(), SymmetricKeySlotId::User)
            .unwrap();
        Cipher {
            name: Some(name),
            ..numbered_cipher(n)
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

    /// The ids of the ciphers `repository` streams, in its order. A memory repository has no
    /// particular order, but streams its ciphers in the same one each time it is unchanged.
    async fn streamed_ids(repository: &Arc<dyn Repository<Cipher>>) -> Vec<Option<CipherId>> {
        let chunks: Vec<_> = Arc::clone(repository).stream(1).collect().await;
        chunks
            .into_iter()
            .flat_map(|chunk| chunk.unwrap())
            .map(|cipher| cipher.id)
            .collect()
    }

    /// What a cipher out of the stream says, for comparing whole outputs.
    #[derive(Debug, PartialEq)]
    enum Outcome {
        Decrypted { id: Option<CipherId>, name: String },
        Failed(Option<CipherId>),
    }

    /// Each cipher out of `chunks`, in order.
    fn outcomes(chunks: Vec<Result<DecryptedChunk, DecryptStreamError>>) -> Vec<Outcome> {
        chunks
            .into_iter()
            .flat_map(|chunk| chunk.unwrap())
            .map(|result| match result {
                Ok(view) => Outcome::Decrypted {
                    id: view.id,
                    name: view.name,
                },
                Err(cipher) => Outcome::Failed(cipher.id),
            })
            .collect()
    }

    #[tokio::test]
    async fn keeps_each_failure_in_its_place() {
        let (client, key_store) = unlocked_client().await;
        let bad = cipher_of_unknown_organization();
        let blank_name = cipher_with_undecryptable_name(4);
        let repository = repository_of(vec![
            numbered_cipher(1),
            bad.clone(),
            numbered_cipher(3),
            blank_name.clone(),
        ])
        .await;
        let order = streamed_ids(&repository).await;

        let chunks: Vec<_> = decrypted_list_stream(Ok(repository), key_store, client, 3)
            .collect()
            .await;

        let expected: Vec<_> = order
            .into_iter()
            .map(|id| match id {
                id if id == bad.id => Outcome::Failed(id),
                id if id == blank_name.id => Outcome::Decrypted {
                    id,
                    name: String::new(),
                },
                id => Outcome::Decrypted {
                    id,
                    name: "234234".to_owned(),
                },
            })
            .collect();
        assert_eq!(outcomes(chunks), expected);
    }

    #[tokio::test]
    async fn keeps_each_failure_in_its_place_when_strict() {
        let (client, key_store) = strict_client().await;
        let bad = cipher_of_unknown_organization();
        let bad_name = cipher_with_undecryptable_name(4);
        let repository = repository_of(vec![
            numbered_cipher(1),
            bad.clone(),
            numbered_cipher(3),
            bad_name.clone(),
        ])
        .await;
        let order = streamed_ids(&repository).await;

        let chunks: Vec<_> = decrypted_list_stream(Ok(repository), key_store, client, 3)
            .collect()
            .await;

        let expected: Vec<_> = order
            .into_iter()
            .map(|id| {
                if id == bad.id || id == bad_name.id {
                    Outcome::Failed(id)
                } else {
                    Outcome::Decrypted {
                        id,
                        name: "234234".to_owned(),
                    }
                }
            })
            .collect();
        assert_eq!(outcomes(chunks), expected);
    }

    #[tokio::test]
    async fn streams_every_cipher_in_chunks() {
        let (client, key_store) = unlocked_client().await;
        let ciphers: Vec<Cipher> = (1..=5).map(numbered_cipher).collect();
        let repository = repository_of(ciphers.clone()).await;

        let chunks: Vec<_> = decrypted_list_stream(Ok(repository), key_store, client, 2)
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
        let (client, key_store) = unlocked_client().await;
        let repository = repository_of(Vec::new()).await;

        let chunks: Vec<_> = decrypted_list_stream(Ok(repository), key_store, client, 2)
            .collect()
            .await;

        assert!(chunks.is_empty());
    }

    #[tokio::test]
    async fn ends_with_vault_locked_when_locked() {
        let (client, key_store) = unlocked_client().await;
        let repository = repository_of((1..=3).map(numbered_cipher).collect()).await;
        key_store.clear();

        let chunks: Vec<_> = decrypted_list_stream(Ok(repository), key_store, client, 2)
            .collect()
            .await;

        assert_eq!(chunks.len(), 1);
        assert!(matches!(chunks[0], Err(DecryptStreamError::VaultLocked)));
    }

    #[tokio::test]
    async fn ends_with_the_repository_error_when_there_is_no_repository() {
        let (client, key_store) = unlocked_client().await;
        let missing = Err(RepositoryError::Internal("no cipher repository".to_owned()));

        let chunks: Vec<_> = decrypted_list_stream(missing, key_store, client, 2)
            .collect()
            .await;

        assert_eq!(chunks.len(), 1);
        assert!(matches!(chunks[0], Err(DecryptStreamError::Repository(_))));
    }
}

use std::{future::Future, sync::Arc};

use bitwarden_state::repository::RepositoryStream;
use futures::StreamExt;

pub struct UniffiRepositoryBridge<T>(pub T);

impl<T: ?Sized> UniffiRepositoryBridge<Arc<T>> {
    pub fn new(store: Arc<T>) -> Arc<Self> {
        Arc::new(UniffiRepositoryBridge(store))
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for UniffiRepositoryBridge<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Where an [`iterator_stream`] is in reading a foreign repository's iterator.
enum IteratorState<Open, I> {
    /// The iterator has not been asked for yet.
    Unopened(Open),
    /// The iterator is open and has more batches.
    Open(I),
    /// The iterator returned an error, so the stream has ended.
    Failed,
}

/// Reads a foreign repository through its batched iterator, in chunks of up to `chunk_size` items
/// (at least one).
///
/// `open` asks the repository for its iterator when the stream is first polled. Then `next` asks
/// the iterator for the next batch whenever the chunks of the previous batch are used up. A batch
/// larger than `chunk_size` is split into chunks, a smaller batch is one chunk, and an empty batch
/// is skipped. The stream ends when `next` returns `None`, and after the first error, of either
/// `open` or `next`.
pub(crate) fn iterator_stream<V, I, Open, Next, NextFut>(
    open: Open,
    next: Next,
    chunk_size: usize,
) -> RepositoryStream<V>
where
    V: Send + 'static,
    I: Clone + Send + 'static,
    Open: FnOnce() -> Result<I, RepositoryError> + Send + 'static,
    Next: Fn(I) -> NextFut + Send + Sync + 'static,
    NextFut: Future<Output = Result<Option<Vec<V>>, RepositoryError>> + Send + 'static,
{
    let chunk_size = chunk_size.max(1);
    let next = Arc::new(next);
    let batches = futures::stream::unfold(IteratorState::Unopened(open), move |state| {
        let next = Arc::clone(&next);
        async move {
            let iterator = match state {
                IteratorState::Unopened(open) => match open() {
                    Ok(iterator) => iterator,
                    Err(error) => return Some((Err(error.into()), IteratorState::Failed)),
                },
                IteratorState::Open(iterator) => iterator,
                IteratorState::Failed => return None,
            };
            match next(iterator.clone()).await {
                Ok(Some(batch)) => Some((Ok(batch), IteratorState::Open(iterator))),
                Ok(None) => None,
                Err(error) => Some((Err(error.into()), IteratorState::Failed)),
            }
        }
    });
    batches
        .flat_map(move |batch| match batch {
            Ok(batch) => futures::stream::iter(chunks_of(batch, chunk_size).map(Ok)).left_stream(),
            Err(error) => futures::stream::iter([Err(error)]).right_stream(),
        })
        .boxed()
}

/// Splits `items` into chunks of up to `chunk_size` items, in order. No chunks for no items.
fn chunks_of<V>(items: Vec<V>, chunk_size: usize) -> impl Iterator<Item = Vec<V>> {
    let mut items = items.into_iter();
    std::iter::from_fn(move || {
        let chunk: Vec<V> = items.by_ref().take(chunk_size).collect();
        (!chunk.is_empty()).then_some(chunk)
    })
}

#[derive(uniffi::Error, thiserror::Error, Debug)]
pub enum RepositoryError {
    #[error("Internal error: {0}")]
    Internal(String),
}

// Need to implement this From<> impl in order to handle unexpected callback errors.  See the
// following page in the Uniffi user guide:
// <https://mozilla.github.io/uniffi-rs/foreign_traits.html#error-handling>
impl From<uniffi::UnexpectedUniFFICallbackError> for RepositoryError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Internal(e.reason)
    }
}

impl From<RepositoryError> for bitwarden_state::repository::RepositoryError {
    fn from(e: RepositoryError) -> Self {
        match e {
            RepositoryError::Internal(msg) => Self::Internal(msg),
        }
    }
}

/// This macro creates a Uniffi repository trait and its implementation for the
/// [bitwarden_state::repository::Repository] trait
macro_rules! create_uniffi_repositories {
    ( $container_name:ident ; $( $qualified_type_name:ty, $type_name:ident, $field_name:ident, $repo_name:ident, $iterator_name:ident );+ $(;)? ) => {

        #[derive(::uniffi::Record)]
        pub struct $container_name {
            $(
                pub $field_name: Option<::std::sync::Arc<dyn $repo_name>>,
            )+
        }

        impl $container_name {
            pub fn register_all(self, client: &bitwarden_core::platform::StateClient) {
                $(
                    if let Some(repo) = self.$field_name {
                        let bridge = $crate::platform::repository::UniffiRepositoryBridge::new(repo);
                        client.register_client_managed(bridge);
                    }
                )+
            }
        }

        $(
            #[::uniffi::export(with_foreign)]
            #[::async_trait::async_trait]
            pub trait $repo_name: Send + Sync {
                async fn get(
                    &self,
                    id: String,
                ) -> Result<Option<$qualified_type_name>, $crate::platform::repository::RepositoryError>;
                async fn list(&self)
                    -> Result<Vec<$qualified_type_name>, $crate::platform::repository::RepositoryError>;
                async fn set(
                    &self,
                    id: String,
                    value: $qualified_type_name,
                ) -> Result<(), $crate::platform::repository::RepositoryError>;
                async fn set_bulk(
                    &self,
                    values: std::collections::HashMap<String, $qualified_type_name>,
                ) -> Result<(), $crate::platform::repository::RepositoryError>;
                async fn remove(
                    &self,
                    id: String,
                ) -> Result<(), $crate::platform::repository::RepositoryError>;
                async fn remove_bulk(
                    &self,
                    keys: Vec<String>,
                ) -> Result<(), $crate::platform::repository::RepositoryError>;
                async fn remove_all(&self)
                    -> Result<(), $crate::platform::repository::RepositoryError>;

                async fn has(
                    &self,
                    id: String,
                ) -> Result<bool, $crate::platform::repository::RepositoryError>;

                /// Returns an iterator over every item in the repository, which the SDK reads a
                /// batch at a time, so it does not need to hold every item at once. See the
                /// iterator for what it must do.
                ///
                /// `batch_size` is how many items the SDK would like per batch. It is only a hint,
                /// see the iterator.
                ///
                /// The SDK calls this synchronously on one of its own threads, so it must return
                /// quickly: only create the iterator here, and do all reading in its `next`.
                fn list_iter(
                    &self,
                    batch_size: u32,
                ) -> Result<
                    ::std::sync::Arc<dyn $iterator_name>,
                    $crate::platform::repository::RepositoryError,
                >;
            }

            /// Every item in a client-managed repository, a batch per `next` call. The
            /// repository returns it from `list_iter`.
            ///
            /// The repository decides how to produce the batches, for example with a query per
            /// call that only keeps the key of the last item read, or with an open database
            /// cursor. A repository with no reason to read lazily can return every item from
            /// `list` as one batch, and then `None`.
            ///
            /// The `batch_size` passed to `list_iter` is only a hint: any batch size works. The
            /// SDK splits a larger batch into pieces of `batch_size`, and skips an empty batch.
            ///
            /// The SDK calls `next` again only after the previous call returned. It stops after
            /// `None` or the first error, and can stop earlier when it no longer needs the items.
            /// Each call can run on a different thread, so an implementation must not depend on
            /// the thread it runs on. For example, with Core Data, perform the fetch on the
            /// queue of the managed object context.
            #[::uniffi::export(with_foreign)]
            #[::async_trait::async_trait]
            pub trait $iterator_name: Send + Sync {
                /// Returns the next batch of items, or `None` when every item has been returned.
                async fn next(
                    &self,
                ) -> Result<Option<Vec<$qualified_type_name>>, $crate::platform::repository::RepositoryError>;
            }

            #[async_trait::async_trait]
            impl bitwarden_state::repository::Repository<$qualified_type_name>
                for $crate::platform::repository::UniffiRepositoryBridge<Arc<dyn $repo_name>>
            {
                async fn get(
                    &self,
                    key: <$qualified_type_name as bitwarden_state::repository::RepositoryItem>::Key,
                ) -> Result<Option<$qualified_type_name>, bitwarden_state::repository::RepositoryError> {
                    let key = key.to_string();
                    self.0.get(key).await.map_err(Into::into)
                }
                async fn list(&self) -> Result<Vec<$qualified_type_name>, bitwarden_state::repository::RepositoryError> {
                    self.0.list().await.map_err(Into::into)
                }
                async fn set(
                    &self,
                    key: <$qualified_type_name as bitwarden_state::repository::RepositoryItem>::Key,
                    value: $qualified_type_name,
                ) -> Result<(), bitwarden_state::repository::RepositoryError> {
                    let key = key.to_string();
                    self.0.set(key, value).await.map_err(Into::into)
                }
                async fn set_bulk(
                    &self,
                    values: Vec<(<$qualified_type_name as bitwarden_state::repository::RepositoryItem>::Key, $qualified_type_name)>,
                ) -> Result<(), bitwarden_state::repository::RepositoryError> {
                    let map = values.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
                    self.0.set_bulk(map).await.map_err(Into::into)
                }
                async fn remove(
                    &self,
                    key: <$qualified_type_name as bitwarden_state::repository::RepositoryItem>::Key,
                ) -> Result<(), bitwarden_state::repository::RepositoryError> {
                    let key = key.to_string();
                    self.0.remove(key).await.map_err(Into::into)
                }
                async fn remove_bulk(
                    &self,
                    keys: Vec<<$qualified_type_name as bitwarden_state::repository::RepositoryItem>::Key>,
                ) -> Result<(), bitwarden_state::repository::RepositoryError> {
                    let keys = keys.into_iter().map(|k| k.to_string()).collect();
                    self.0.remove_bulk(keys).await.map_err(Into::into)
                }
                async fn remove_all(&self) -> Result<(), bitwarden_state::repository::RepositoryError> {
                    self.0.remove_all().await.map_err(Into::into)
                }

                fn stream(
                    self: Arc<Self>,
                    chunk_size: usize,
                ) -> bitwarden_state::repository::RepositoryStream<$qualified_type_name> {
                    let batch_size = u32::try_from(chunk_size.max(1)).unwrap_or(u32::MAX);
                    $crate::platform::repository::iterator_stream(
                        move || self.0.list_iter(batch_size),
                        |iterator: Arc<dyn $iterator_name>| async move { iterator.next().await },
                        chunk_size,
                    )
                }
            }
        )+
    };
}

pub(super) use create_uniffi_repositories;

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, VecDeque},
        sync::Mutex,
    };

    use bitwarden_state::repository::Repository;
    use bitwarden_vault::{Folder, FolderId};
    use futures::StreamExt;

    use super::*;
    use crate::platform::{FolderIterator, FolderRepository};

    type Batch = Result<Option<Vec<Folder>>, RepositoryError>;

    /// A foreign folder iterator that returns `batches` in order, then `None`. Counts its calls.
    struct ScriptedIterator {
        batches: Mutex<VecDeque<Batch>>,
        calls: Mutex<usize>,
    }

    #[async_trait::async_trait]
    impl FolderIterator for ScriptedIterator {
        async fn next(&self) -> Batch {
            *self.calls.lock().unwrap() += 1;
            self.batches.lock().unwrap().pop_front().unwrap_or(Ok(None))
        }
    }

    /// A foreign folder repository that only supports `list_iter`. It returns `iterator`, or fails
    /// when there is none, and records the `batch_size` of each call.
    struct IteratedFolders {
        iterator: Option<Arc<ScriptedIterator>>,
        list_iters: Mutex<Vec<u32>>,
    }

    impl IteratedFolders {
        fn new(batches: Option<Vec<Batch>>) -> Arc<Self> {
            Arc::new(Self {
                iterator: batches.map(|batches| {
                    Arc::new(ScriptedIterator {
                        batches: Mutex::new(batches.into()),
                        calls: Mutex::new(0),
                    })
                }),
                list_iters: Mutex::new(Vec::new()),
            })
        }

        fn next_calls(&self) -> usize {
            *self.iterator.as_ref().unwrap().calls.lock().unwrap()
        }
    }

    #[async_trait::async_trait]
    impl FolderRepository for IteratedFolders {
        async fn get(&self, _id: String) -> Result<Option<Folder>, RepositoryError> {
            unimplemented!()
        }
        async fn list(&self) -> Result<Vec<Folder>, RepositoryError> {
            unimplemented!()
        }
        async fn set(&self, _id: String, _value: Folder) -> Result<(), RepositoryError> {
            unimplemented!()
        }
        async fn set_bulk(&self, _values: HashMap<String, Folder>) -> Result<(), RepositoryError> {
            unimplemented!()
        }
        async fn remove(&self, _id: String) -> Result<(), RepositoryError> {
            unimplemented!()
        }
        async fn remove_bulk(&self, _keys: Vec<String>) -> Result<(), RepositoryError> {
            unimplemented!()
        }
        async fn remove_all(&self) -> Result<(), RepositoryError> {
            unimplemented!()
        }
        async fn has(&self, _id: String) -> Result<bool, RepositoryError> {
            unimplemented!()
        }
        fn list_iter(&self, batch_size: u32) -> Result<Arc<dyn FolderIterator>, RepositoryError> {
            self.list_iters.lock().unwrap().push(batch_size);
            match &self.iterator {
                Some(iterator) => Ok(iterator.clone()),
                None => Err(RepositoryError::Internal("unavailable".to_owned())),
            }
        }
    }

    fn folder(n: u128) -> Folder {
        Folder {
            id: Some(FolderId::new(uuid::Uuid::from_u128(n))),
            name: "2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8="
                .parse()
                .unwrap(),
            revision_date: "2024-01-01T00:00:00Z".parse().unwrap(),
        }
    }

    fn folders(ns: impl IntoIterator<Item = u128>) -> Vec<Folder> {
        ns.into_iter().map(folder).collect()
    }

    /// The ids of each chunk of a stream, or the error message of a failed chunk.
    type ChunkIds = Result<Vec<Option<FolderId>>, String>;

    async fn read(repository: Arc<IteratedFolders>, chunk_size: usize) -> Vec<ChunkIds> {
        let bridge = UniffiRepositoryBridge::new(repository as Arc<dyn FolderRepository>);
        bridge
            .stream(chunk_size)
            .map(|chunk| match chunk {
                Ok(chunk) => Ok(chunk.into_iter().map(|folder| folder.id).collect()),
                Err(error) => Err(error.to_string()),
            })
            .collect()
            .await
    }

    fn ids(ns: impl IntoIterator<Item = u128>) -> ChunkIds {
        Ok(folders(ns).into_iter().map(|folder| folder.id).collect())
    }

    #[tokio::test]
    async fn bridge_splits_a_batch_larger_than_the_chunk_size() {
        let repository = IteratedFolders::new(Some(vec![
            Ok(Some(folders(1..=5))),
            Ok(Some(folders(6..=6))),
        ]));
        let bridge = UniffiRepositoryBridge::new(repository.clone() as Arc<dyn FolderRepository>);

        let stream = bridge.stream(2);
        assert!(repository.list_iters.lock().unwrap().is_empty());
        let chunks: Vec<_> = stream.map(|chunk| chunk.unwrap().len()).collect().await;

        // The rest of the first batch is not merged with the next batch.
        assert_eq!(chunks, vec![2, 2, 1, 1]);
        assert_eq!(*repository.list_iters.lock().unwrap(), vec![2]);
        assert_eq!(repository.next_calls(), 3);
    }

    #[tokio::test]
    async fn bridge_keeps_batches_smaller_than_the_chunk_size_apart() {
        let repository = IteratedFolders::new(Some(vec![
            Ok(Some(folders(1..=1))),
            Ok(Some(folders(2..=3))),
            Ok(Some(folders(4..=4))),
        ]));

        let chunks = read(repository.clone(), 3).await;

        assert_eq!(chunks, vec![ids(1..=1), ids(2..=3), ids(4..=4)]);
        assert_eq!(repository.next_calls(), 4);
    }

    #[tokio::test]
    async fn bridge_skips_empty_batches() {
        let repository = IteratedFolders::new(Some(vec![
            Ok(Some(Vec::new())),
            Ok(Some(folders(1..=2))),
            Ok(Some(Vec::new())),
            Ok(Some(folders(3..=3))),
        ]));

        let chunks = read(repository.clone(), 2).await;

        assert_eq!(chunks, vec![ids(1..=2), ids(3..=3)]);
        assert_eq!(repository.next_calls(), 5);
    }

    #[tokio::test]
    async fn bridge_splits_a_single_batch_iterator_into_chunks() {
        let repository = IteratedFolders::new(Some(vec![Ok(Some(folders(1..=5)))]));

        let chunks = read(repository.clone(), 2).await;

        assert_eq!(chunks, vec![ids(1..=2), ids(3..=4), ids(5..=5)]);
        assert_eq!(repository.next_calls(), 2);
    }

    #[tokio::test]
    async fn bridge_asks_for_batches_of_at_least_one_item() {
        let repository = IteratedFolders::new(Some(vec![]));

        let chunks = read(repository.clone(), 0).await;

        assert!(chunks.is_empty());
        assert_eq!(*repository.list_iters.lock().unwrap(), vec![1]);
    }

    #[tokio::test]
    async fn bridge_stream_ends_after_the_first_error_of_next() {
        let repository = IteratedFolders::new(Some(vec![
            Ok(Some(folders(1..=2))),
            Err(RepositoryError::Internal("unavailable".to_owned())),
            Ok(Some(folders(3..=4))),
        ]));

        let chunks = read(repository.clone(), 2).await;

        assert_eq!(
            chunks,
            vec![ids(1..=2), Err("Internal error: unavailable".to_owned())]
        );
        assert_eq!(repository.next_calls(), 2);
    }

    #[tokio::test]
    async fn bridge_stream_ends_after_an_error_of_list_iter() {
        let repository = IteratedFolders::new(None);

        let chunks = read(repository.clone(), 2).await;

        assert_eq!(chunks, vec![Err("Internal error: unavailable".to_owned())]);
        assert_eq!(*repository.list_iters.lock().unwrap(), vec![2]);
    }
}

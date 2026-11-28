use std::{any::TypeId, sync::Arc};

use futures::{StreamExt, stream::BoxStream};

use crate::{persist::Persist, registry::StateRegistryError};

/// An error resulting from operations on a repository.
#[derive(thiserror::Error, Debug)]
pub enum RepositoryError {
    /// An internal unspecified error.
    #[error("Internal error: {0}")]
    Internal(String),

    /// A serialization or deserialization error.
    #[error(transparent)]
    Serde(#[from] serde_json::Error),

    /// An internal database error.
    #[error(transparent)]
    Database(#[from] crate::sdk_managed::DatabaseError),

    /// State registry error.
    #[error(transparent)]
    StateRegistry(#[from] StateRegistryError),
}

/// Extension trait for `Option<Arc<dyn Repository<V>>>` to concisely require that a repository
/// is available.
pub trait RepositoryOption<V: RepositoryItem> {
    /// Returns a reference to the repository, or a
    /// [`StateRegistryError::DatabaseNotInitialized`] error if it is `None`.
    fn require(&self) -> Result<&Arc<dyn Repository<V>>, RepositoryError>;
}

impl<V: RepositoryItem> RepositoryOption<V> for Option<Arc<dyn Repository<V>>> {
    fn require(&self) -> Result<&Arc<dyn Repository<V>>, RepositoryError> {
        self.as_ref()
            .ok_or(StateRegistryError::DatabaseNotInitialized.into())
    }
}

/// Chunks of items read from a repository, as [`Repository::stream`] returns them. An `Err` ends
/// the stream.
pub type RepositoryStream<V> = BoxStream<'static, Result<Vec<V>, RepositoryError>>;

/// This trait represents a generic repository interface, capable of storing and retrieving
/// items using a key-value API.
#[async_trait::async_trait]
pub trait Repository<V: RepositoryItem>: Send + Sync {
    /// Retrieves an item from the repository by its key.
    async fn get(&self, key: V::Key) -> Result<Option<V>, RepositoryError>;
    /// Lists all items in the repository.
    async fn list(&self) -> Result<Vec<V>, RepositoryError>;

    /// Lists all items in the repository in chunks of up to `chunk_size` items (at least one), in
    /// no particular order.
    ///
    /// A repository that can read its items lazily overrides this, so a caller holds one chunk at
    /// a time. The default reads every item with [`Self::list`] when the stream is first polled
    /// and hands them out in chunks.
    fn stream(self: Arc<Self>, chunk_size: usize) -> RepositoryStream<V>
    where
        Self: 'static,
    {
        futures::stream::once(async move { self.list().await })
            .flat_map(move |items| match items {
                Ok(items) => futures::stream::iter(chunks_of(items, chunk_size).map(Ok)).boxed(),
                Err(error) => futures::stream::iter([Err(error)]).boxed(),
            })
            .boxed()
    }
    /// Sets an item in the repository with the specified key.
    async fn set(&self, key: V::Key, value: V) -> Result<(), RepositoryError>;
    /// Sets multiple items in the repository.
    async fn set_bulk(&self, values: Vec<(V::Key, V)>) -> Result<(), RepositoryError>;
    /// Removes an item from the repository by its key.
    async fn remove(&self, key: V::Key) -> Result<(), RepositoryError>;
    /// Removes multiple items from the repository by their keys.
    async fn remove_bulk(&self, keys: Vec<V::Key>) -> Result<(), RepositoryError>;
    /// Removes all items from the repository.
    async fn remove_all(&self) -> Result<(), RepositoryError>;

    /// Replaces all items in the repository with the provided values. This is a convenience method
    /// that first removes all existing items and then sets the new items in bulk.
    ///
    /// In the future we may want to explore using revision dates to optimize this operation.
    async fn replace_all(&self, values: Vec<(V::Key, V)>) -> Result<(), RepositoryError> {
        self.remove_all().await?;
        self.set_bulk(values).await
    }
}

/// Splits `items` into chunks of up to `chunk_size` items (at least one), in order.
pub(crate) fn chunks_of<V>(items: Vec<V>, chunk_size: usize) -> impl Iterator<Item = Vec<V>> {
    let chunk_size = chunk_size.max(1);
    let mut items = items.into_iter();
    std::iter::from_fn(move || {
        let chunk: Vec<V> = items.by_ref().take(chunk_size).collect();
        (!chunk.is_empty()).then_some(chunk)
    })
}

/// This trait is used to mark types that can be stored in a repository.
/// It should not be implemented manually; instead, users should
/// use the [crate::register_repository_item] macro to register their item types.
///
/// The [`Persist`] bound is what makes an item storable by SDK-managed repositories. It is
/// satisfied automatically by any type that is serializable and thread-safe.
pub trait RepositoryItem: Internal + Persist {
    /// The name of the type implementing this trait.
    const NAME: &'static str;

    /// The type used as a key in the Repository.
    ///
    /// `FromStr` is required so the debug-capabilities surface can address items
    /// by a string key; every current key type (String and the `uuid_newtype!`
    /// ids) already implements it, so this bound is satisfied everywhere.
    type Key: ToString + std::str::FromStr + Send + Sync + 'static;

    /// Returns the `TypeId` of the type implementing this trait.
    fn type_id() -> TypeId {
        TypeId::of::<Self>()
    }

    /// Returns metadata about the repository item type.
    fn data() -> RepositoryItemData {
        RepositoryItemData::new::<Self>()
    }
}

/// This struct holds metadata about a registered repository item type.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct RepositoryItemData {
    type_id: TypeId,
    name: &'static str,
    /// Dev-only: monomorphized get/set/list shims for this type's repository,
    /// captured here because `new::<T>` is the point where `T` is still known.
    #[cfg(feature = "debug-capabilities")]
    pub(crate) debug: crate::debug::DebugRepo,
}

impl RepositoryItemData {
    /// Create a new `RepositoryItemData` from a type that implements `RepositoryItem`.
    pub fn new<T: RepositoryItem>() -> Self {
        Self {
            type_id: TypeId::of::<T>(),
            name: T::NAME,
            #[cfg(feature = "debug-capabilities")]
            debug: crate::debug::DebugRepo::for_type::<T>(),
        }
    }

    /// Get the `TypeId` of the registered type.
    pub fn type_id(&self) -> TypeId {
        self.type_id
    }
    /// Get the name of the registered type.
    /// This name is guaranteed to be a valid identifier.
    pub fn name(&self) -> &'static str {
        self.name
    }
}

/// Validate that the provided name will be a valid identifier at compile time.
/// This is intentionally limited to ensure compatibility with current and future storage backends.
/// For example, SQLite tables must not begin with a number or contain special characters.
/// Valid characters are a-z, A-Z, and underscore (_).
pub const fn validate_registry_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        // Check if character is alphabetic (a-z, A-Z) or underscore
        if !((byte >= b'a' && byte <= b'z') || (byte >= b'A' && byte <= b'Z') || byte == b'_') {
            return false;
        }
        i += 1;
    }
    true
}

/// Represents a set of migrations for multiple repositories in a database migration process.
#[derive(Debug, Clone)]
pub struct RepositoryMigrations {
    pub(crate) steps: Vec<RepositoryMigrationStep>,
    // This is used only by indexedDB
    #[allow(dead_code)]
    pub(crate) version: u32,
}

/// Represents a single step for a repository in a database migration process.
#[derive(Debug, Clone, Copy)]
pub enum RepositoryMigrationStep {
    /// Add a new repository.
    Add(RepositoryItemData),
    /// Remove an existing repository.
    Remove(RepositoryItemData),
}

impl RepositoryMigrations {
    /// Create a new `RepositoryMigrations` with the given steps. The version is derived from the
    /// number of steps.
    pub fn new(steps: Vec<RepositoryMigrationStep>) -> Self {
        Self {
            version: steps.len() as u32,
            steps,
        }
    }

    /// Converts the migration steps into a list of unique repository item data.
    pub fn into_repository_items(self) -> Vec<RepositoryItemData> {
        let mut map = std::collections::HashMap::new();
        for step in self.steps {
            match step {
                RepositoryMigrationStep::Add(data) => {
                    map.insert(data.type_id, data);
                }
                RepositoryMigrationStep::Remove(data) => {
                    map.remove(&data.type_id);
                }
            }
        }
        map.into_values().collect()
    }
}

/// Register a type for use in a repository. The type must only be registered once in the crate
/// where it's defined. The provided name must be unique and not be changed.
#[macro_export]
macro_rules! register_repository_item {
    ($keyty:ty => $ty:ty, $name:literal) => {
        const _: () = {
            impl $crate::repository::___internal::Internal for $ty {}
            impl $crate::repository::RepositoryItem for $ty {
                const NAME: &'static str = $name;
                type Key = $keyty;
            }
            assert!(
                $crate::repository::validate_registry_name($name),
                concat!(
                    "Repository name '",
                    $name,
                    "' must contain only alphabetic characters and underscores"
                )
            )
        };
    };
}

/// This code is not meant to be used directly, users of this crate should use the
/// [crate::register_repository_item] macro to register their types.
#[doc(hidden)]
pub mod ___internal {

    // This trait is in an internal module to try to forbid users from implementing `RepositoryItem`
    // directly.
    pub trait Internal {}
}
pub(crate) use ___internal::Internal;

#[cfg(test)]
mod tests {
    use futures::StreamExt;

    use super::*;

    #[test]
    fn test_validate_name() {
        assert!(validate_registry_name("valid"));
        assert!(validate_registry_name("Valid_Name"));
        assert!(!validate_registry_name("Invalid-Name"));
        assert!(!validate_registry_name("Invalid Name"));
        assert!(!validate_registry_name("Invalid.Name"));
        assert!(!validate_registry_name("Invalid123"));
    }

    #[test]
    fn chunks_of_keeps_order_and_boundaries() {
        let chunks: Vec<Vec<u32>> = chunks_of((1..=5).collect(), 2).collect();
        assert_eq!(chunks, vec![vec![1, 2], vec![3, 4], vec![5]]);
    }

    #[test]
    fn chunks_of_an_empty_list_is_empty() {
        assert_eq!(chunks_of(Vec::<u32>::new(), 2).count(), 0);
    }

    #[test]
    fn chunks_of_size_zero_takes_one_at_a_time() {
        assert_eq!(chunks_of(vec![1, 2], 0).count(), 2);
    }

    #[test]
    fn chunks_of_more_than_the_list_is_one_chunk() {
        let chunks: Vec<Vec<u32>> = chunks_of(vec![1, 2], 10).collect();
        assert_eq!(chunks, vec![vec![1, 2]]);
    }

    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct ListItem(String);
    crate::register_repository_item!(String => ListItem, "ListOnlyItem");

    /// A repository that only implements `list`, to exercise the default `stream`.
    struct ListOnly(Result<Vec<ListItem>, String>);

    #[async_trait::async_trait]
    impl Repository<ListItem> for ListOnly {
        async fn get(&self, _key: String) -> Result<Option<ListItem>, RepositoryError> {
            Ok(None)
        }
        async fn list(&self) -> Result<Vec<ListItem>, RepositoryError> {
            self.0.clone().map_err(RepositoryError::Internal)
        }
        async fn set(&self, _key: String, _value: ListItem) -> Result<(), RepositoryError> {
            Ok(())
        }
        async fn set_bulk(&self, _values: Vec<(String, ListItem)>) -> Result<(), RepositoryError> {
            Ok(())
        }
        async fn remove(&self, _key: String) -> Result<(), RepositoryError> {
            Ok(())
        }
        async fn remove_bulk(&self, _keys: Vec<String>) -> Result<(), RepositoryError> {
            Ok(())
        }
        async fn remove_all(&self) -> Result<(), RepositoryError> {
            Ok(())
        }
    }

    async fn collect_stream(
        repository: ListOnly,
        chunk_size: usize,
    ) -> Vec<Result<Vec<ListItem>, RepositoryError>> {
        Arc::new(repository).stream(chunk_size).collect().await
    }

    fn items(names: &[&str]) -> Vec<ListItem> {
        names
            .iter()
            .map(|name| ListItem(name.to_string()))
            .collect()
    }

    #[tokio::test]
    async fn default_stream_chunks_the_list_in_order() {
        let chunks = collect_stream(ListOnly(Ok(items(&["a", "b", "c"]))), 2).await;

        let chunks: Vec<Vec<ListItem>> = chunks.into_iter().map(Result::unwrap).collect();
        assert_eq!(chunks, vec![items(&["a", "b"]), items(&["c"])]);
    }

    #[tokio::test]
    async fn default_stream_of_an_empty_repository_is_empty() {
        assert!(collect_stream(ListOnly(Ok(Vec::new())), 2).await.is_empty());
    }

    #[tokio::test]
    async fn default_stream_ends_with_the_list_error() {
        let chunks = collect_stream(ListOnly(Err("unavailable".to_owned())), 2).await;

        assert_eq!(chunks.len(), 1);
        assert!(matches!(&chunks[0], Err(RepositoryError::Internal(m)) if m == "unavailable"));
    }
}

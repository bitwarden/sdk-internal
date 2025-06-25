use std::any::TypeId;

/// An error resulting from operations on a repository.
#[derive(thiserror::Error, Debug)]
pub enum RepositoryError {
    /// An internal unspecified error.
    #[error("Internal error: {0}")]
    Internal(String),
}

/// This trait represents a generic repository interface, capable of storing and retrieving
/// items using a key-value API.
#[async_trait::async_trait]
pub trait Repository<V: RepositoryItem>: Send + Sync {
    /// Retrieves an item from the repository by its key.
    async fn get(&self, key: String) -> Result<Option<V>, RepositoryError>;
    /// Lists all items in the repository.
    async fn list(&self) -> Result<Vec<V>, RepositoryError>;
    /// Sets an item in the repository with the specified key.
    async fn set(&self, key: String, value: V) -> Result<(), RepositoryError>;
    /// Removes an item from the repository by its key.
    async fn remove(&self, key: String) -> Result<(), RepositoryError>;
}

/// This trait is used to mark types that can be stored in a repository.
/// It should not be implemented manually; instead, users should
/// use the [crate::register_repository_item] macro to register their item types.
pub trait RepositoryItem: Internal + Send + Sync + 'static {
    /// The name of the type implementing this trait.
    const NAME: &'static str;
    /// Returns the `TypeId` of the type implementing this trait.
    fn type_id() -> TypeId {
        TypeId::of::<Self>()
    }
}

/// Register a type for use in a repository. The type must only be registered once in the crate
/// where it's defined. The provided name must be unique and not be changed.
#[macro_export]
macro_rules! register_repository_item {
    ($ty:ty, $name:literal) => {
        const _: () = {
            impl $crate::repository::___internal::Internal for $ty {}
            impl $crate::repository::RepositoryItem for $ty {
                const NAME: &'static str = $name;
            }
        };
    };
}

/// This code is not meant to be used directly, users of this crate should use the
/// [crate::register_repository_item] macro to register their types.
#[doc(hidden)]
pub mod ___internal {

    // This trait is just to try to discourage users from implementing `RepositoryItem` directly.
    pub trait Internal {}
}
pub(crate) use ___internal::Internal;

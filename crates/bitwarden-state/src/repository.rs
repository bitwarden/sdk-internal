use std::any::TypeId;

use crate::registry::RepositoryNotFoundError;

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

    /// Repository not found.
    #[error(transparent)]
    RepositoryNotFound(#[from] RepositoryNotFoundError),
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
}

impl RepositoryItemData {
    /// Create a new `RepositoryItemData` from a type that implements `RepositoryItem`.
    pub fn new<T: RepositoryItem + ?Sized>() -> Self {
        Self {
            type_id: TypeId::of::<T>(),
            name: T::NAME,
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
}

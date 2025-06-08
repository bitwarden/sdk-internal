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
/// use the [register_repository_item] macro to register their item types.
pub trait RepositoryItem: Internal + Send + Sync + 'static {
    /// The name of the type implementing this trait.
    const NAME: &'static str;
    /// Returns the `TypeId` of the type implementing this trait.
    fn type_id() -> TypeId {
        TypeId::of::<Self>()
    }
}

/// Register a type for use in a repository. The type must only be registered once in the crate
/// where it's defined. The provided name must be unique and not be changed. Through the use of the
/// `inventory` crate, this macro will register the type globally and
/// [test_utils::verify_no_duplicate_registrations] will ensure that no duplicate registrations
/// exist.
#[macro_export]
macro_rules! register_repository_item {
    ($ty:ty, $name:literal, $type:expr) => {
        const _: () = {
            impl $crate::repository::___internal::Internal for $ty {}
            impl $crate::repository::RepositoryItem for $ty {
                const NAME: &'static str = $name;
            }
            use $crate::repository::___internal::RepositoryItemRegistrationType::*;
            $crate::repository::___internal::submit! {
                $crate::repository::___internal::RepositoryItemRegistration::new::<$ty>($name, $type)
            }
        };
    };
}

/// This code is used to register types that can be stored in a repository.
/// It's not meant to be used directly, users of this crate should use the
/// [register_repository_item] macro to register their types.
#[doc(hidden)]
pub mod ___internal {
    use super::*;

    // This trait is just to try to discourage users from implementing `RepositoryItem` directly.
    pub trait Internal {}

    /// This enum indicated what kind of repository registration is being performed.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum RepositoryItemRegistrationType {
        ClientManaged,
        SdkManaged,
        Both,
    }

    impl RepositoryItemRegistrationType {
        pub fn is_client_managed(&self) -> bool {
            matches!(self, Self::ClientManaged | Self::Both)
        }
        pub fn is_sdk_managed(&self) -> bool {
            matches!(self, Self::SdkManaged | Self::Both)
        }
    }

    #[derive(Debug)]
    pub struct RepositoryItemRegistration {
        pub(crate) name: &'static str,
        /// The type identifier of the repository item. We're using a function pointer because
        /// [TypeId::of] is not const stable.
        pub(crate) type_id: fn() -> TypeId,
        pub(crate) rtype: RepositoryItemRegistrationType,
    }

    impl RepositoryItemRegistration {
        /// Creates a new `RepositoryRegistration` for the given type.
        pub const fn new<T: RepositoryItem>(
            name: &'static str,
            rtype: RepositoryItemRegistrationType,
        ) -> Self {
            Self {
                name,
                type_id: || T::type_id(),
                rtype,
            }
        }

        pub(crate) fn iter() -> impl Iterator<Item = &'static RepositoryItemRegistration> {
            inventory::iter::<RepositoryItemRegistration>()
        }
    }

    inventory::collect!(RepositoryItemRegistration);
    pub use inventory::submit;
}
pub(crate) use ___internal::{Internal, RepositoryItemRegistration};

#[cfg(test)]
mod tests {
    use super::*;

    struct TestItem;

    register_repository_item!(TestItem, "TestItem", SdkManaged);

    #[test]
    fn test_repository_item_registration() {
        let registered: Vec<_> = RepositoryItemRegistration::iter().collect();
        // We can't really test the exact number, as they might be registered in different crates.
        assert!(!registered.is_empty(), "No repository items registered");
    }

    #[test]
    pub fn verify_no_duplicate_registrations() {
        crate::repository::test_utils::verify_no_duplicate_registrations();
    }
}

#[doc(hidden)]
pub mod test_utils {
    /// Verify that no duplicate repository item registrations exist.
    /// This needs to be called in the final SDK crates (WASM, UniFFI, CLI, ...) to ensure that all
    /// registrations are checked.
    pub fn verify_no_duplicate_registrations() {
        use crate::repository::___internal::RepositoryItemRegistration;

        let mut seen_names = std::collections::HashSet::new();
        let mut seen_ids = std::collections::HashSet::new();

        for reg in RepositoryItemRegistration::iter() {
            assert!(
                seen_names.insert(reg.name),
                "Duplicate repository registration name: {}",
                reg.name
            );
            assert!(
                seen_ids.insert((reg.type_id)()),
                "Duplicate repository registration id: {}",
                reg.name
            );
        }
    }
}

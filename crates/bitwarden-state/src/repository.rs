use std::{
    any::{Any, TypeId},
    collections::HashMap,
    sync::Arc,
};

/// An error resulting from operations on a repository.
#[derive(thiserror::Error, Debug)]
pub enum RepositoryError {
    /// An internal unspecified error.
    #[error("Internal error: {0}")]
    Internal(String),
}

/// This trait is used to mark types that can be stored in a repository.
/// It provides a method to retrieve the `TypeId` of the type, which is used to
/// differentiate between different types of entries in the repository.
pub trait RepositoryItem: 'static {
    /// Returns the `TypeId` of the type implementing this trait.
    fn type_id(&self) -> TypeId {
        TypeId::of::<Self>()
    }

    /// Returns the name of the type implementing this trait.
    fn name(&self) -> &'static str {
        std::any::type_name::<Self>()
    }
}

/// This trait represents a generic repository interface, capable of storing and retrieving
/// items using a key-value API.
#[async_trait::async_trait]
pub trait Repository<T>: Send + Sync {
    /// Retrieves an item from the repository by its key.
    async fn get(&self, key: String) -> Result<Option<T>, RepositoryError>;
    /// Lists all items in the repository.
    async fn list(&self) -> Result<Vec<T>, RepositoryError>;
    /// Sets an item in the repository with the specified key.
    async fn set(&self, key: String, value: T) -> Result<(), RepositoryError>;
    /// Removes an item from the repository by its key.
    async fn remove(&self, key: String) -> Result<(), RepositoryError>;
}

/// A map that holds repositories for different types, allowing for dynamic retrieval
/// based on type identifiers.
#[derive(Default)]
pub struct RepositoryMap {
    stores: HashMap<TypeId, Box<dyn Any + Send + Sync>>,
}

impl std::fmt::Debug for RepositoryMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepositoryMap")
            .field("stores", &self.stores.keys())
            .finish()
    }
}

impl RepositoryMap {
    /// Creates a new empty `RepositoryMap`.
    pub fn new() -> Self {
        RepositoryMap {
            stores: HashMap::new(),
        }
    }

    /// Inserts a repository into the map, associating it with its type.
    pub fn insert<T: 'static>(&mut self, value: Arc<dyn Repository<T>>) {
        self.stores.insert(TypeId::of::<T>(), Box::new(value));
    }

    /// Retrieves a repository from the map given its type.
    pub fn get<T: 'static>(&self) -> Option<Arc<dyn Repository<T>>> {
        self.stores
            .get(&TypeId::of::<T>())
            .and_then(|boxed| boxed.downcast_ref::<Arc<dyn Repository<T>>>())
            .map(Arc::clone)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! impl_repository {
        ($name:ident, $ty:ty) => {
            #[async_trait::async_trait]
            impl Repository<$ty> for $name {
                async fn get(&self, _key: String) -> Result<Option<$ty>, RepositoryError> {
                    Ok(Some(self.0.clone()))
                }
                async fn list(&self) -> Result<Vec<$ty>, RepositoryError> {
                    unimplemented!()
                }
                async fn set(&self, _key: String, _value: $ty) -> Result<(), RepositoryError> {
                    unimplemented!()
                }
                async fn remove(&self, _key: String) -> Result<(), RepositoryError> {
                    unimplemented!()
                }
            }
        };
    }

    #[derive(PartialEq, Eq, Debug)]
    struct TestA(usize);
    #[derive(PartialEq, Eq, Debug)]
    struct TestB(String);
    #[derive(PartialEq, Eq, Debug)]
    struct TestC(Vec<u8>);

    impl_repository!(TestA, usize);
    impl_repository!(TestB, String);
    impl_repository!(TestC, Vec<u8>);

    #[tokio::test]
    async fn test_repository_map() {
        let a = Arc::new(TestA(145832));
        let b = Arc::new(TestB("test".to_string()));
        let c = Arc::new(TestC(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]));

        let mut map = RepositoryMap::new();

        async fn get<T: 'static>(map: &RepositoryMap) -> Option<T> {
            map.get::<T>().unwrap().get(String::new()).await.unwrap()
        }

        assert!(map.get::<usize>().is_none());
        assert!(map.get::<String>().is_none());
        assert!(map.get::<Vec<u8>>().is_none());

        map.insert(a.clone());
        assert_eq!(get(&map).await, Some(a.0));
        assert!(map.get::<String>().is_none());
        assert!(map.get::<Vec<u8>>().is_none());

        map.insert(b.clone());
        assert_eq!(get(&map).await, Some(a.0));
        assert_eq!(get(&map).await, Some(b.0.clone()));
        assert!(map.get::<Vec<u8>>().is_none());

        map.insert(c.clone());
        assert_eq!(get(&map).await, Some(a.0));
        assert_eq!(get(&map).await, Some(b.0.clone()));
        assert_eq!(get(&map).await, Some(c.0.clone()));
    }
}

use std::{
    any::{Any, TypeId},
    collections::HashMap,
    sync::{Arc, OnceLock, RwLock},
};

use bitwarden_error::bitwarden_error;
use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;

use crate::{
    repository::{Repository, RepositoryItem, RepositoryItemData, RepositoryMigrations},
    sdk_managed::{Database, DatabaseConfiguration, SystemDatabase},
};

/// A registry that contains repositories for different types of items.
/// These repositories can be either managed by the client or by the SDK itself.
pub struct StateRegistry {
    sdk_managed: RwLock<Vec<RepositoryItemData>>,
    client_managed: RwLock<HashMap<TypeId, Box<dyn Any + Send + Sync>>>,

    database: OnceLock<SystemDatabase>,
}

impl std::fmt::Debug for StateRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateRegistry").finish()
    }
}

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum StateRegistryError {
    #[error("Database is already initialized")]
    DatabaseAlreadyInitialized,
    #[error("Database is not initialized")]
    DatabaseNotInitialized,

    #[error(transparent)]
    Database(#[from] crate::sdk_managed::DatabaseError),
}

/// Repository not found.
#[derive(Debug, Error)]
#[error("Repository not found for the requested type")]
pub struct RepositoryNotFoundError;

impl StateRegistry {
    /// Creates a new empty `StateRegistry`.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        StateRegistry {
            client_managed: RwLock::new(HashMap::new()),
            database: OnceLock::new(),
            sdk_managed: RwLock::new(Vec::new()),
        }
    }

    // TODO: Ideally we'd do this in new, but that would mean making the client initialization
    // async.
    // TODO: This function needs to be provided some configuration to know where to open the
    // database. For Sqlite:
    // - A folder path where the files will be stored.
    // - A user ID to create a unique database file per user?
    //
    // For WASM indexedDB:
    // - A database name to use for the indexedDB (Some prefix to avoid conflicts + user ID?)

    /// Initializes the database used for sdk-managed repositories.
    pub async fn initialize_database(
        &self,
        configuration: DatabaseConfiguration,
        migrations: RepositoryMigrations,
    ) -> Result<(), StateRegistryError> {
        if self.database.get().is_some() {
            return Err(StateRegistryError::DatabaseAlreadyInitialized);
        }
        let _ = self
            .database
            .set(SystemDatabase::initialize(configuration, migrations.clone()).await?);

        *self
            .sdk_managed
            .write()
            .expect("RwLock should not be poisoned") = migrations.into_repository_items();

        Ok(())
    }

    /// Registers a client-managed repository into the map, associating it with its type.
    pub fn register_client_managed<T: RepositoryItem>(&self, value: Arc<dyn Repository<T>>) {
        self.client_managed
            .write()
            .expect("RwLock should not be poisoned")
            .insert(TypeId::of::<T>(), Box::new(value));
    }

    /// Retrieves a client-managed repository from the map given its type.
    pub fn get_client_managed<T: RepositoryItem>(
        &self,
    ) -> Result<Arc<dyn Repository<T>>, RepositoryNotFoundError> {
        self.client_managed
            .read()
            .expect("RwLock should not be poisoned")
            .get(&TypeId::of::<T>())
            .and_then(|boxed| boxed.downcast_ref::<Arc<dyn Repository<T>>>())
            .map(Arc::clone)
            .ok_or(RepositoryNotFoundError)
    }

    /// Retrieves a SDK-managed repository from the database.
    pub fn get_sdk_managed<T: RepositoryItem + Serialize + DeserializeOwned>(
        &self,
    ) -> Result<impl Repository<T>, StateRegistryError> {
        if let Some(db) = self.database.get() {
            Ok(db.get_repository::<T>()?)
        } else {
            Err(StateRegistryError::DatabaseNotInitialized)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        register_repository_item,
        repository::{RepositoryError, RepositoryItem},
    };

    macro_rules! impl_repository {
        ($name:ident, $ty:ty) => {
            #[async_trait::async_trait]
            impl Repository<$ty> for $name {
                async fn get(&self, _key: String) -> Result<Option<$ty>, RepositoryError> {
                    Ok(Some(TestItem(self.0.clone())))
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
    #[derive(PartialEq, Eq, Debug)]
    struct TestItem<T>(T);

    register_repository_item!(TestItem<usize>, "TestItem_usize");
    register_repository_item!(TestItem<String>, "TestItem_String");
    register_repository_item!(TestItem<Vec<u8>>, "TestItem_Vec");

    impl_repository!(TestA, TestItem<usize>);
    impl_repository!(TestB, TestItem<String>);
    impl_repository!(TestC, TestItem<Vec<u8>>);

    #[tokio::test]
    async fn test_repository_map() {
        let a = Arc::new(TestA(145832));
        let b = Arc::new(TestB("test".to_string()));
        let c = Arc::new(TestC(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]));

        let map = StateRegistry::new();

        async fn get<T: RepositoryItem>(map: &StateRegistry) -> Option<T> {
            map.get_client_managed::<T>()
                .unwrap()
                .get(String::new())
                .await
                .unwrap()
        }

        assert!(map.get_client_managed::<TestItem<usize>>().is_err());
        assert!(map.get_client_managed::<TestItem<String>>().is_err());
        assert!(map.get_client_managed::<TestItem<Vec<u8>>>().is_err());

        map.register_client_managed(a.clone());
        assert_eq!(get(&map).await, Some(TestItem(a.0)));
        assert!(map.get_client_managed::<TestItem<String>>().is_err());
        assert!(map.get_client_managed::<TestItem<Vec<u8>>>().is_err());

        map.register_client_managed(b.clone());
        assert_eq!(get(&map).await, Some(TestItem(a.0)));
        assert_eq!(get(&map).await, Some(TestItem(b.0.clone())));
        assert!(map.get_client_managed::<TestItem<Vec<u8>>>().is_err());

        map.register_client_managed(c.clone());
        assert_eq!(get(&map).await, Some(TestItem(a.0)));
        assert_eq!(get(&map).await, Some(TestItem(b.0.clone())));
        assert_eq!(get(&map).await, Some(TestItem(c.0.clone())));
    }
}

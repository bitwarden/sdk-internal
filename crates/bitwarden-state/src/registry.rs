use std::{
    any::{Any, TypeId},
    collections::HashMap,
    sync::{Arc, RwLock},
};

use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::{
    repository::{RepositoryItem, RepositoryMigrations, RepositoryTrait, handle::Repository},
    sdk_managed::{Database, DatabaseConfiguration, DatabaseError, MemoryDatabase, SystemDatabase},
    values::{Key, Setting, Value, ValueItem, ValueKey},
};

/// A registry that contains repositories for different types of items.
/// These repositories can be either managed by the client or by the SDK itself.
pub struct StateRegistry {
    database: SystemDatabase,
    client_managed: RwLock<HashMap<TypeId, Box<dyn Any + Send + Sync>>>,
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
    #[error("Database is not initialized")]
    DatabaseNotInitialized,

    #[error(transparent)]
    Database(#[from] DatabaseError),
}

impl StateRegistry {
    /// Creates a new `StateRegistry` backed by an in-memory database.
    pub fn new_with_memory_db() -> Self {
        StateRegistry {
            database: SystemDatabase::Memory(MemoryDatabase::new()),
            client_managed: RwLock::new(HashMap::new()),
        }
    }

    /// Creates a new `StateRegistry` backed by a database.
    pub async fn new_with_db(
        configuration: DatabaseConfiguration,
        migrations: RepositoryMigrations,
    ) -> Result<Self, DatabaseError> {
        let database = SystemDatabase::initialize(configuration, migrations.clone()).await?;
        Ok(StateRegistry {
            database,
            client_managed: RwLock::new(HashMap::new()),
        })
    }

    /// Get a handle to the value identified by `K`.
    pub fn value<K: ValueKey>(&self) -> Value<K> {
        Value::new(self.backend::<ValueItem>())
    }

    /// Get a handle to a setting by its type-safe key.
    ///
    /// Superseded by [`Self::value`], which cannot fail and identifies the value by type.
    /// Removed once every caller has migrated.
    ///
    /// # Errors
    /// This method never fails, but returns a Result for backwards compatibility.
    pub fn setting<T>(&self, key: Key<T>) -> Result<Setting<T>, StateRegistryError> {
        Ok(Setting::new(self.backend::<ValueItem>(), key))
    }

    /// Registers a client-managed repository into the map, associating it with its type.
    pub fn register_client_managed<T: RepositoryItem>(&self, value: Arc<dyn RepositoryTrait<T>>) {
        self.client_managed
            .write()
            .expect("RwLock should not be poisoned")
            .insert(TypeId::of::<T>(), Box::new(value));
    }

    /// Get a handle to the repository storing items of type `T`, preferring a client-managed
    /// repository and falling back to SDK-managed storage.
    pub fn repo<T: RepositoryItem>(&self) -> Repository<T> {
        Repository::new(self.backend::<T>())
    }

    /// Resolve the backing implementation for `T`: client-managed if registered, SDK-managed
    /// otherwise.
    fn backend<T: RepositoryItem>(&self) -> Arc<dyn RepositoryTrait<T>> {
        self.get_client_managed::<T>()
            .unwrap_or_else(|| self.database.get_repository::<T>())
    }

    /// Retrieves a client-managed repository, without falling back to SDK-managed storage.
    fn get_client_managed<T: RepositoryItem>(&self) -> Option<Arc<dyn RepositoryTrait<T>>> {
        self.client_managed
            .read()
            .expect("RwLock should not be poisoned")
            .get(&TypeId::of::<T>())
            .and_then(|boxed| boxed.downcast_ref::<Arc<dyn RepositoryTrait<T>>>())
            .map(Arc::clone)
    }

    /// Get a repository with fallback: prefer client-managed, fall back to SDK-managed.
    ///
    /// Superseded by [`Self::repo`], which returns a [`Repository`] handle and cannot
    /// fail. Removed once every caller has migrated.
    ///
    /// # Errors
    /// This method never fails, but returns a Result for backwards compatibility.
    pub fn get<T>(&self) -> Result<Arc<dyn RepositoryTrait<T>>, StateRegistryError>
    where
        T: RepositoryItem,
    {
        Ok(self.backend::<T>())
    }

    /// Wipes all state from this registry, and deletes any files or databases associated with it.
    /// Intended to be used during logout, where the Client will be dropped right after.
    ///
    /// # Warning
    ///
    /// This closes the SDK-managed database and deletes persistent storage (SQLite file + WAL/SHM,
    /// IndexedDB database). Outstanding repository handles will return
    /// [`RepositoryError::Closed`](crate::repository::RepositoryError::Closed) on subsequent
    /// operations. Client-managed repositories are dropped, not asked to delete their contents —
    /// clients own their own teardown.
    pub async fn wipe(&self) -> Result<(), DatabaseError> {
        // Clear client-managed first so a failure in the persistent-store wipe
        // still releases the in-memory Arc references.
        self.client_managed
            .write()
            .expect("RwLock should not be poisoned")
            .clear();
        self.database.wipe().await
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
            impl RepositoryTrait<$ty> for $name {
                async fn get(&self, _key: String) -> Result<Option<$ty>, RepositoryError> {
                    Ok(Some(TestItem(self.0.clone())))
                }
                async fn list(&self) -> Result<Vec<$ty>, RepositoryError> {
                    unimplemented!()
                }
                async fn set(&self, _key: String, _value: $ty) -> Result<(), RepositoryError> {
                    unimplemented!()
                }
                async fn set_bulk(
                    &self,
                    _values: Vec<(String, $ty)>,
                ) -> Result<(), RepositoryError> {
                    unimplemented!()
                }
                async fn remove(&self, _key: String) -> Result<(), RepositoryError> {
                    unimplemented!()
                }
                async fn remove_bulk(&self, _keys: Vec<String>) -> Result<(), RepositoryError> {
                    unimplemented!()
                }
                async fn remove_all(&self) -> Result<(), RepositoryError> {
                    unimplemented!()
                }
            }
        };
    }

    use serde::{Deserialize, Serialize};

    #[derive(PartialEq, Eq, Debug)]
    struct TestA(usize);
    #[derive(PartialEq, Eq, Debug)]
    struct TestB(String);
    #[derive(PartialEq, Eq, Debug)]
    struct TestC(Vec<u8>);
    #[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
    struct TestItem<T>(T);

    register_repository_item!(String => TestItem<usize>, "TestItem_usize");
    register_repository_item!(String => TestItem<String>, "TestItem_String");
    register_repository_item!(String => TestItem<Vec<u8>>, "TestItem_Vec");

    impl_repository!(TestA, TestItem<usize>);
    impl_repository!(TestB, TestItem<String>);
    impl_repository!(TestC, TestItem<Vec<u8>>);

    #[tokio::test]
    async fn test_state_registry() {
        let a = Arc::new(TestA(145832));
        let b = Arc::new(TestB("test".to_string()));
        let c = Arc::new(TestC(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]));

        let map = StateRegistry::new_with_memory_db();

        async fn get<T: RepositoryItem>(map: &StateRegistry) -> Option<T>
        where
            T::Key: Default,
        {
            map.get_client_managed::<T>()
                .unwrap()
                .get(Default::default())
                .await
                .unwrap()
        }

        assert!(map.get_client_managed::<TestItem<usize>>().is_none());
        assert!(map.get_client_managed::<TestItem<String>>().is_none());
        assert!(map.get_client_managed::<TestItem<Vec<u8>>>().is_none());

        map.register_client_managed(a.clone());
        assert_eq!(get(&map).await, Some(TestItem(a.0)));
        assert!(map.get_client_managed::<TestItem<String>>().is_none());
        assert!(map.get_client_managed::<TestItem<Vec<u8>>>().is_none());

        map.register_client_managed(b.clone());
        assert_eq!(get(&map).await, Some(TestItem(a.0)));
        assert_eq!(get(&map).await, Some(TestItem(b.0.clone())));
        assert!(map.get_client_managed::<TestItem<Vec<u8>>>().is_none());

        map.register_client_managed(c.clone());
        assert_eq!(get(&map).await, Some(TestItem(a.0)));
        assert_eq!(get(&map).await, Some(TestItem(b.0.clone())));
        assert_eq!(get(&map).await, Some(TestItem(c.0.clone())));
    }

    #[tokio::test]
    async fn test_fallback_client_managed_found() {
        let registry = StateRegistry::new_with_memory_db();
        let test_repo = Arc::new(TestA(12345));

        registry.register_client_managed(test_repo.clone());

        let repo = registry.get::<TestItem<usize>>().unwrap();
        let result = repo.get(String::new()).await.unwrap();

        assert_eq!(result, Some(TestItem(12345)));
    }

    #[tokio::test]
    async fn test_new_with_memory_db_sync() {
        // Construct in sync context (no .await on the constructor itself)
        let registry = StateRegistry::new_with_memory_db();
        // Database must be accessible via async get after sync construction
        let repo = registry.get::<TestItem<usize>>().unwrap();
        let result = repo.get(String::new()).await;
        // Should return Ok(None) — key not found, not an error
        // (Note: TestItem<usize> is registered in this test module already)
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_wipe_disconnects_outstanding_repository_handles() {
        let registry = StateRegistry::new_with_memory_db();
        let repo = registry.get::<TestItem<usize>>().unwrap();
        repo.set(String::new(), TestItem(42usize)).await.unwrap();

        registry.wipe().await.unwrap();

        assert!(matches!(
            repo.get(String::new()).await,
            Err(RepositoryError::Closed)
        ));
        assert!(matches!(repo.list().await, Err(RepositoryError::Closed)));
    }

    #[tokio::test]
    async fn test_wipe_clears_client_managed() {
        let registry = StateRegistry::new_with_memory_db();
        registry.register_client_managed(Arc::new(TestA(99)));

        registry.wipe().await.unwrap();

        // Client-managed is gone; falls through to SDK-managed (now closed).
        let repo = registry.get::<TestItem<usize>>().unwrap();
        assert!(matches!(
            repo.get(String::new()).await,
            Err(RepositoryError::Closed)
        ));
    }

    #[tokio::test]
    async fn test_wipe_is_idempotent() {
        let registry = StateRegistry::new_with_memory_db();
        registry.wipe().await.unwrap();
        registry.wipe().await.unwrap();
    }

    #[tokio::test]
    async fn test_repo_get_errors_when_absent() {
        let registry = StateRegistry::new_with_memory_db();
        let repo = registry.repo::<TestItem<usize>>();

        assert!(matches!(
            repo.get(String::new()).await,
            Err(RepositoryError::NotFound)
        ));
        assert_eq!(repo.get_opt(String::new()).await.unwrap(), None);
        assert!(!repo.has(String::new()).await.unwrap());
    }

    #[tokio::test]
    async fn test_repo_get_returns_value_when_present() {
        let registry = StateRegistry::new_with_memory_db();
        let repo = registry.repo::<TestItem<usize>>();

        repo.set(String::new(), TestItem(7usize)).await.unwrap();

        assert_eq!(repo.get(String::new()).await.unwrap(), TestItem(7));
        assert_eq!(
            repo.get_opt(String::new()).await.unwrap(),
            Some(TestItem(7))
        );
        assert!(repo.has(String::new()).await.unwrap());
    }

    #[tokio::test]
    async fn test_repo_prefers_client_managed() {
        let registry = StateRegistry::new_with_memory_db();
        registry.register_client_managed(Arc::new(TestA(4242)));

        // TestA always answers with its own value, so reading a key never written to the
        // SDK-managed database proves the client-managed repository was used.
        let repo = registry.repo::<TestItem<usize>>();
        assert_eq!(repo.get(String::new()).await.unwrap(), TestItem(4242));
    }

    #[tokio::test]
    async fn test_repo_reports_closed_after_wipe() {
        let registry = StateRegistry::new_with_memory_db();
        let repo = registry.repo::<TestItem<usize>>();
        repo.set(String::new(), TestItem(1usize)).await.unwrap();

        registry.wipe().await.unwrap();

        // Closed must not be reported as NotFound — the distinction is the whole point of
        // keeping the variant.
        assert!(matches!(
            repo.get(String::new()).await,
            Err(RepositoryError::Closed)
        ));
        assert!(matches!(
            repo.get_opt(String::new()).await,
            Err(RepositoryError::Closed)
        ));
    }

    #[tokio::test]
    async fn test_repo_handle_is_cloneable_and_shares_storage() {
        let registry = StateRegistry::new_with_memory_db();
        let repo = registry.repo::<TestItem<usize>>();
        let clone = repo.clone();

        repo.set(String::new(), TestItem(11usize)).await.unwrap();

        assert_eq!(clone.get(String::new()).await.unwrap(), TestItem(11));
    }

    #[tokio::test]
    async fn test_setting_on_memory_db() {
        use crate::register_setting_key;
        register_setting_key!(const TEST_SETTING: String = "test_registry_setting_key");

        let registry = StateRegistry::new_with_memory_db();
        let setting = registry.setting(TEST_SETTING).unwrap();

        // Value must not exist initially
        assert_eq!(setting.get().await.unwrap(), None::<String>);

        // Update and read back
        setting.update("hello".to_string()).await.unwrap();
        assert_eq!(setting.get().await.unwrap(), Some("hello".to_string()));

        // Delete and confirm gone
        setting.delete().await.unwrap();
        assert_eq!(setting.get().await.unwrap(), None::<String>);
    }

    #[tokio::test]
    async fn test_value_on_memory_db() {
        use crate::{register_value_key, values::ValueError};
        register_value_key!(TEST_VALUE: String = "test_registry_value_key");

        let registry = StateRegistry::new_with_memory_db();
        let value = registry.value::<TEST_VALUE>();

        assert!(matches!(value.get().await, Err(ValueError::NotFound)));
        assert_eq!(value.get_opt().await.unwrap(), None);

        value.set("hello".to_string()).await.unwrap();
        assert_eq!(value.get().await.unwrap(), "hello");
        assert_eq!(value.get_opt().await.unwrap(), Some("hello".to_string()));

        value.remove().await.unwrap();
        assert!(matches!(value.get().await, Err(ValueError::NotFound)));
    }

    #[tokio::test]
    async fn test_value_and_setting_share_storage() {
        use crate::register_value_key;
        register_value_key!(SHARED: String = "test_shared_key");

        let registry = StateRegistry::new_with_memory_db();
        let setting = registry.setting(SHARED).unwrap();
        let value = registry.value::<SHARED>();

        // Both spellings address the same stored value, so call sites can migrate one at a time.
        setting
            .update("written-as-setting".to_string())
            .await
            .unwrap();
        assert_eq!(value.get().await.unwrap(), "written-as-setting");

        value.set("written-as-value".to_string()).await.unwrap();
        assert_eq!(
            setting.get().await.unwrap(),
            Some("written-as-value".to_string())
        );
    }

    #[tokio::test]
    async fn test_values_are_isolated_by_key() {
        use crate::register_value_key;
        register_value_key!(THEME: String = "test_theme_key");
        register_value_key!(LOCALE: String = "test_locale_key");

        let registry = StateRegistry::new_with_memory_db();
        let theme = registry.value::<THEME>();
        let locale = registry.value::<LOCALE>();

        theme.set("dark".to_string()).await.unwrap();
        locale.set("en-US".to_string()).await.unwrap();

        theme.remove().await.unwrap();
        assert_eq!(locale.get().await.unwrap(), "en-US");
    }

    #[tokio::test]
    async fn test_value_reports_closed_after_wipe() {
        use crate::{register_value_key, values::ValueError};
        register_value_key!(WIPED: String = "test_wiped_key");

        let registry = StateRegistry::new_with_memory_db();
        let value = registry.value::<WIPED>();
        value.set("gone".to_string()).await.unwrap();

        registry.wipe().await.unwrap();

        // Closed must not be reported as NotFound.
        assert!(matches!(
            value.get().await,
            Err(ValueError::Repository(RepositoryError::Closed))
        ));
    }
}

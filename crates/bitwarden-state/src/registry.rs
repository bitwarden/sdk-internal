use std::sync::Arc;

use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::{
    any_map::AnyMap,
    persist::Persist,
    persisted_value::{
        PersistedValue, PersistedValueError, PersistedValueKey, PersistedValueTrait,
    },
    repository::{Repository, RepositoryItem, RepositoryMigrations},
    sdk_managed::{Database, DatabaseConfiguration, DatabaseError, MemoryDatabase, SystemDatabase},
};

/// A registry that contains repositories for different types of items.
/// These repositories can be either managed by the client or by the SDK itself.
pub struct StateRegistry {
    database: SystemDatabase,
    client_managed: AnyMap,
    client_managed_values: AnyMap<&'static str>,
    /// Dev-only index of per-type get/set/list shims backing the generic debug
    /// browse. Populated at registration (both client- and SDK-managed), where
    /// the concrete type is known. See [`crate::debug`].
    #[cfg(feature = "debug-capabilities")]
    pub(crate) debug: crate::debug::DebugRegistry,
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
            client_managed: AnyMap::new(),
            client_managed_values: AnyMap::new(),
            #[cfg(feature = "debug-capabilities")]
            debug: crate::debug::DebugRegistry::new(),
        }
    }

    /// Creates a new `StateRegistry` backed by a database.
    pub async fn new_with_db(
        configuration: DatabaseConfiguration,
        migrations: RepositoryMigrations,
    ) -> Result<Self, DatabaseError> {
        let database = SystemDatabase::initialize(configuration, migrations.clone()).await?;
        let registry = StateRegistry {
            database,
            client_managed: AnyMap::new(),
            client_managed_values: AnyMap::new(),
            #[cfg(feature = "debug-capabilities")]
            debug: crate::debug::DebugRegistry::new(),
        };
        // Capture debug shims for every SDK-managed type declared in the migrations.
        #[cfg(feature = "debug-capabilities")]
        registry.debug.register_migrations(&migrations);
        Ok(registry)
    }

    /// Get a handle to a persisted value by its type-safe key, preferring a client-managed backend
    /// and falling back to SDK-managed storage.
    ///
    /// The handle resolves its backend now, so a client-managed backend registered afterwards is
    /// not seen by it.
    pub fn value<K: PersistedValueKey>(&self) -> PersistedValue<K> {
        PersistedValue::new(self.value_backend::<K::Value>(K::NAME))
    }

    /// Registers a client-managed backend for the persisted value identified by `K`, replacing any
    /// earlier registration.
    pub fn register_client_managed_value<K: PersistedValueKey>(
        &self,
        value: impl Into<PersistedValue<K>>,
    ) {
        self.client_managed_values
            .insert_at(K::NAME, value.into().backend);
    }

    fn value_backend<T: Persist>(&self, name: &'static str) -> Arc<dyn PersistedValueTrait<T>> {
        match self
            .client_managed_values
            .get_at::<Arc<dyn PersistedValueTrait<T>>>(&name)
        {
            Some(Some(backend)) => backend,
            Some(None) => Arc::new(MismatchedValueType(name)),
            None => self.database.get_persisted_value::<T>(name),
        }
    }

    /// Registers a client-managed repository into the map, associating it with its type.
    pub fn register_client_managed<T: RepositoryItem>(&self, value: Arc<dyn Repository<T>>) {
        self.client_managed.insert(value);
        #[cfg(feature = "debug-capabilities")]
        self.debug.register::<T>();
    }

    /// Retrieves a client-managed repository from the map given its type.
    fn get_client_managed<T: RepositoryItem>(&self) -> Option<Arc<dyn Repository<T>>> {
        self.client_managed.get()
    }

    /// Retrieves a SDK-managed repository from the database.
    fn get_sdk_managed<T: RepositoryItem>(
        &self,
    ) -> Result<Arc<dyn Repository<T>>, StateRegistryError> {
        Ok(self.database.get_repository::<T>())
    }

    /// Get a repository with fallback: prefer client-managed, fall back to SDK-managed.
    ///
    /// This method first attempts to retrieve a client-managed repository. If not found,
    /// it falls back to an SDK-managed repository. Both are returned as `Arc<dyn Repository<T>>`.
    ///
    /// # Errors
    /// This method never fails, but returns a Result for backwards compatibility.
    pub fn get<T>(&self) -> Result<Arc<dyn Repository<T>>, StateRegistryError>
    where
        T: RepositoryItem,
    {
        if let Some(repo) = self.get_client_managed::<T>() {
            return Ok(repo);
        }

        self.get_sdk_managed::<T>()
    }

    /// Wipes all state from this registry, and deletes any files or databases associated with it.
    /// Intended to be used during logout, where the Client will be dropped right after.
    ///
    /// # Warning
    ///
    /// This closes the SDK-managed database and deletes persistent storage (SQLite file + WAL/SHM,
    /// IndexedDB database). Outstanding [`Repository`] handles will return
    /// [`DatabaseError::Closed`] on subsequent operations. Client-managed repositories and
    /// persisted values are also cleared.
    pub async fn wipe(&self) -> Result<(), DatabaseError> {
        // Clear client-managed first so a failure in the persistent-store wipe
        // still releases the in-memory Arc references.
        self.client_managed.clear();
        self.client_managed_values.clear();
        self.database.wipe().await
    }
}

/// Backend for a name that is client-managed under a different value type. Two keys sharing a name
/// is a bug; failing keeps it from silently reading SDK-managed storage instead.
struct MismatchedValueType(&'static str);

impl MismatchedValueType {
    fn error(&self) -> PersistedValueError {
        PersistedValueError::Internal(format!(
            "'{}' is client-managed with a different value type",
            self.0
        ))
    }
}

#[async_trait::async_trait]
impl<T: Persist> PersistedValueTrait<T> for MismatchedValueType {
    async fn get(&self) -> Result<Option<T>, PersistedValueError> {
        Err(self.error())
    }
    async fn set(&self, _value: T) -> Result<(), PersistedValueError> {
        Err(self.error())
    }
    async fn remove(&self) -> Result<(), PersistedValueError> {
        Err(self.error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        register_repository_item,
        repository::{RepositoryError, RepositoryItem},
        sdk_managed::DatabaseError,
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
    /// A second implementation for the same item type as [`TestA`].
    #[derive(PartialEq, Eq, Debug)]
    struct TestD(usize);
    #[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
    struct TestItem<T>(T);

    register_repository_item!(String => TestItem<usize>, "TestItem_usize");
    register_repository_item!(String => TestItem<String>, "TestItem_String");
    register_repository_item!(String => TestItem<Vec<u8>>, "TestItem_Vec");

    impl_repository!(TestA, TestItem<usize>);
    impl_repository!(TestB, TestItem<String>);
    impl_repository!(TestC, TestItem<Vec<u8>>);
    impl_repository!(TestD, TestItem<usize>);

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
            Err(RepositoryError::Database(DatabaseError::Closed))
        ));
        assert!(matches!(
            repo.list().await,
            Err(RepositoryError::Database(DatabaseError::Closed))
        ));
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
            Err(RepositoryError::Database(DatabaseError::Closed))
        ));
    }

    #[tokio::test]
    async fn test_wipe_is_idempotent() {
        let registry = StateRegistry::new_with_memory_db();
        registry.wipe().await.unwrap();
        registry.wipe().await.unwrap();
    }

    #[tokio::test]
    async fn test_persisted_value_on_memory_db() {
        use crate::register_persisted_value;
        register_persisted_value!(TEST_VALUE: String = "test_registry_persisted_value_key");

        let registry = StateRegistry::new_with_memory_db();
        let value = registry.value::<TEST_VALUE>();

        // Value must not exist initially
        assert_eq!(value.try_get().await.unwrap(), None::<String>);

        // Update and read back
        value.set("hello".to_string()).await.unwrap();
        assert_eq!(value.try_get().await.unwrap(), Some("hello".to_string()));

        // Delete and confirm gone
        value.remove().await.unwrap();
        assert_eq!(value.try_get().await.unwrap(), None::<String>);
    }

    #[tokio::test]
    async fn test_persisted_values_are_isolated_by_key() {
        use crate::register_persisted_value;
        register_persisted_value!(THEME: String = "test_theme");
        register_persisted_value!(LOCALE: String = "test_locale");

        let registry = StateRegistry::new_with_memory_db();
        let theme = registry.value::<THEME>();
        let locale = registry.value::<LOCALE>();

        theme.set("dark".to_string()).await.unwrap();
        locale.set("en-US".to_string()).await.unwrap();

        theme.remove().await.unwrap();
        assert_eq!(theme.try_get().await.unwrap(), None::<String>);
        assert_eq!(locale.try_get().await.unwrap(), Some("en-US".to_string()));
    }

    #[tokio::test]
    async fn test_persisted_value_is_stored_in_the_persisted_value_table_as_bare_json() {
        use crate::{persisted_value::PersistedValueItem, register_persisted_value};

        #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
        struct Config {
            theme: String,
        }
        register_persisted_value!(CONFIG: Config = "test_config");

        let registry = StateRegistry::new_with_memory_db();
        let value = Config {
            theme: "dark".to_string(),
        };
        let expected = serde_json::to_value(&value).unwrap();
        registry.value::<CONFIG>().set(value).await.unwrap();

        // Storage contract for existing databases: persisted values live in the `PersistedValue`
        // table, addressed by key name, holding the bare serialized value.
        assert_eq!(PersistedValueItem::NAME, "PersistedValue");
        let raw: PersistedValueItem = registry
            .database
            .get::<PersistedValueItem>("test_config")
            .await
            .unwrap()
            .expect("persisted value is present");
        assert_eq!(raw.0, expected);
    }

    #[tokio::test]
    async fn test_persisted_value_reports_closed_after_wipe() {
        use crate::{persisted_value::PersistedValueError, register_persisted_value};
        register_persisted_value!(TEST_VALUE: String = "test_wiped_persisted_value");

        let registry = StateRegistry::new_with_memory_db();
        let value = registry.value::<TEST_VALUE>();
        value.set("hello".to_string()).await.unwrap();

        registry.wipe().await.unwrap();

        assert!(matches!(
            value.try_get().await,
            Err(PersistedValueError::Closed)
        ));
        assert!(matches!(
            value.set("bye".to_string()).await,
            Err(PersistedValueError::Closed)
        ));
    }

    /// The concrete implementation is erased by the coercion to `Arc<dyn Repository<T>>`, so two
    /// implementations of the same item type share a slot and the later registration wins.
    #[tokio::test]
    async fn test_register_client_managed_replaces_previous_implementation() {
        let registry = StateRegistry::new_with_memory_db();

        registry.register_client_managed(Arc::new(TestA(1)));
        registry.register_client_managed(Arc::new(TestD(2)));

        let repo = registry.get_client_managed::<TestItem<usize>>().unwrap();
        assert_eq!(repo.get(String::new()).await.unwrap(), Some(TestItem(2)));
    }

    mod client_managed_values {
        use std::sync::Mutex;

        use super::*;
        use crate::{persisted_value::PersistedValueError, register_persisted_value};

        register_persisted_value!(THEME: String = "client_managed_test_theme");

        struct MemoryValue(Mutex<Option<String>>);

        impl MemoryValue {
            fn with(value: &str) -> Arc<Self> {
                Arc::new(Self(Mutex::new(Some(value.to_string()))))
            }
        }

        #[async_trait::async_trait]
        impl PersistedValueTrait<String> for MemoryValue {
            async fn get(&self) -> Result<Option<String>, PersistedValueError> {
                Ok(self.0.lock().unwrap().clone())
            }
            async fn set(&self, value: String) -> Result<(), PersistedValueError> {
                *self.0.lock().unwrap() = Some(value);
                Ok(())
            }
            async fn remove(&self) -> Result<(), PersistedValueError> {
                *self.0.lock().unwrap() = None;
                Ok(())
            }
        }

        #[tokio::test]
        async fn test_overrides_sdk_managed() {
            let registry = StateRegistry::new_with_memory_db();
            let backend = MemoryValue::with("client");
            registry.register_client_managed_value::<THEME>(backend.clone());

            assert_eq!(registry.value::<THEME>().get().await.unwrap(), "client");
            registry
                .value::<THEME>()
                .set("updated".to_string())
                .await
                .unwrap();
            assert_eq!(backend.0.lock().unwrap().as_deref(), Some("updated"));

            // Nothing reached SDK-managed storage
            assert_eq!(
                registry
                    .database
                    .get_persisted_value::<String>(THEME::NAME)
                    .get()
                    .await
                    .unwrap(),
                None
            );
        }

        #[tokio::test]
        async fn test_unregistered_falls_back_to_sdk_managed() {
            register_persisted_value!(OTHER: String = "client_managed_test_other");

            let registry = StateRegistry::new_with_memory_db();
            registry.register_client_managed_value::<THEME>(MemoryValue::with("client"));

            let other = registry.value::<OTHER>();
            other.set("sdk".to_string()).await.unwrap();
            assert_eq!(
                registry
                    .database
                    .get_persisted_value::<String>(OTHER::NAME)
                    .get()
                    .await
                    .unwrap(),
                Some("sdk".to_string())
            );
        }

        #[tokio::test]
        async fn test_same_name_with_other_type_fails() {
            register_persisted_value!(AS_NUMBER: u32 = "client_managed_test_theme");

            let registry = StateRegistry::new_with_memory_db();
            registry.register_client_managed_value::<THEME>(MemoryValue::with("client"));

            let error = registry.value::<AS_NUMBER>().try_get().await.unwrap_err();
            assert!(matches!(error, PersistedValueError::Internal(_)));
        }

        #[tokio::test]
        async fn test_handle_keeps_the_backend_it_was_built_with() {
            let registry = StateRegistry::new_with_memory_db();
            let before = registry.value::<THEME>();

            registry.register_client_managed_value::<THEME>(MemoryValue::with("client"));

            assert_eq!(before.try_get().await.unwrap(), None);
            assert_eq!(registry.value::<THEME>().get().await.unwrap(), "client");
        }

        #[tokio::test]
        async fn test_wipe_clears_client_managed_values() {
            let registry = StateRegistry::new_with_memory_db();
            registry.register_client_managed_value::<THEME>(MemoryValue::with("client"));

            registry.wipe().await.unwrap();

            // Falls through to SDK-managed storage, which is now closed
            assert!(matches!(
                registry.value::<THEME>().try_get().await,
                Err(PersistedValueError::Closed)
            ));
        }
    }
}

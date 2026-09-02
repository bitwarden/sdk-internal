use std::{
    any::{Any, TypeId},
    collections::HashMap,
    sync::{Arc, RwLock},
};

use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::{
    repository::{Repository, RepositoryItem, RepositoryMigrations},
    sdk_managed::{Database, DatabaseConfiguration, DatabaseError, MemoryDatabase, SystemDatabase},
    settings::{Key, Setting, SettingItem},
};

/// A registry that contains repositories for different types of items.
/// These repositories can be either managed by the client or by the SDK itself.
pub struct StateRegistry {
    database: SystemDatabase,
    client_managed: RwLock<HashMap<TypeId, Box<dyn Any + Send + Sync>>>,
    /// Dev-only: per-type get/set/list shims, keyed by `TypeId`. Populated at
    /// registration (both client-managed and SDK-managed) where the concrete
    /// type is known, so the generic debug surface can address any registered
    /// repository by its string name and key.
    #[cfg(feature = "debug-capabilities")]
    debug_repos: RwLock<HashMap<TypeId, DebugRepo>>,
}

/// A future borrowing the registry, boxed so it can cross a fn pointer.
#[cfg(feature = "debug-capabilities")]
type DebugFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + 'a>>;
/// Shim: list a repository's values as JSON.
#[cfg(feature = "debug-capabilities")]
type DebugListFn = for<'a> fn(&'a StateRegistry) -> DebugFuture<'a, Vec<serde_json::Value>>;
/// Shim: read one item by string key as JSON.
#[cfg(feature = "debug-capabilities")]
type DebugGetFn =
    for<'a> fn(&'a StateRegistry, &'a str) -> DebugFuture<'a, Option<serde_json::Value>>;
/// Shim: write one item by string key.
#[cfg(feature = "debug-capabilities")]
type DebugSetFn = for<'a> fn(&'a StateRegistry, &'a str, serde_json::Value) -> DebugFuture<'a, ()>;

/// Dev-only monomorphized get/set/list shims for one repository type, so the
/// registry can offer generic string-addressed access without naming the type.
#[cfg(feature = "debug-capabilities")]
#[derive(Debug, Clone, Copy)]
pub(crate) struct DebugRepo {
    name: &'static str,
    list: DebugListFn,
    get: DebugGetFn,
    set: DebugSetFn,
}

#[cfg(feature = "debug-capabilities")]
impl DebugRepo {
    /// Capture the shims for a concrete repository type.
    pub(crate) fn for_type<T: RepositoryItem>() -> Self {
        Self {
            name: T::NAME,
            list: |registry| Box::pin(debug_list_repo::<T>(registry)),
            get: |registry, key| Box::pin(debug_get_repo::<T>(registry, key)),
            set: |registry, key, value| Box::pin(debug_set_repo::<T>(registry, key, value)),
        }
    }
}

/// List every item in the `T` repository (client- or SDK-managed) as JSON.
#[cfg(feature = "debug-capabilities")]
async fn debug_list_repo<T: RepositoryItem>(registry: &StateRegistry) -> Vec<serde_json::Value> {
    let Ok(repository) = registry.get::<T>() else {
        return Vec::new();
    };
    match repository.list().await {
        Ok(items) => items
            .iter()
            .filter_map(|item| serde_json::to_value(item).ok())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Read one item from the `T` repository by its string key, as JSON.
#[cfg(feature = "debug-capabilities")]
async fn debug_get_repo<T: RepositoryItem>(
    registry: &StateRegistry,
    key: &str,
) -> Option<serde_json::Value> {
    let key = <T::Key as std::str::FromStr>::from_str(key).ok()?;
    let value = registry.get::<T>().ok()?.get(key).await.ok().flatten()?;
    serde_json::to_value(&value).ok()
}

/// Write one item to the `T` repository at its string key. No-ops on a bad key
/// or a value that does not deserialize to `T`.
#[cfg(feature = "debug-capabilities")]
async fn debug_set_repo<T: RepositoryItem>(
    registry: &StateRegistry,
    key: &str,
    value: serde_json::Value,
) {
    let Ok(key) = <T::Key as std::str::FromStr>::from_str(key) else {
        return;
    };
    let Ok(value) = serde_json::from_value::<T>(value) else {
        return;
    };
    if let Ok(repository) = registry.get::<T>() {
        let _ = repository.set(key, value).await;
    }
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
            #[cfg(feature = "debug-capabilities")]
            debug_repos: RwLock::new(HashMap::new()),
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
            client_managed: RwLock::new(HashMap::new()),
            #[cfg(feature = "debug-capabilities")]
            debug_repos: RwLock::new(HashMap::new()),
        };
        // Register get/set/list shims for every SDK-managed type declared in the
        // migrations, so the debug surface can enumerate and address them.
        #[cfg(feature = "debug-capabilities")]
        {
            let mut debug_repos = registry
                .debug_repos
                .write()
                .expect("RwLock should not be poisoned");
            for item in migrations.into_repository_items() {
                debug_repos.insert(item.type_id(), item.debug);
            }
        }
        Ok(registry)
    }

    /// Get a handle to a setting by its type-safe key.
    pub fn setting<T>(&self, key: Key<T>) -> Result<Setting<T>, StateRegistryError> {
        let repo = self.get::<SettingItem>()?;
        Ok(Setting::new(repo, key))
    }

    /// Registers a client-managed repository into the map, associating it with its type.
    pub fn register_client_managed<T: RepositoryItem>(&self, value: Arc<dyn Repository<T>>) {
        self.client_managed
            .write()
            .expect("RwLock should not be poisoned")
            .insert(TypeId::of::<T>(), Box::new(value));
        // Register get/set/list shims for this client-managed type.
        #[cfg(feature = "debug-capabilities")]
        self.debug_repos
            .write()
            .expect("RwLock should not be poisoned")
            .insert(TypeId::of::<T>(), DebugRepo::for_type::<T>());
    }

    /// Dev-only: names of every registered repository (client- and SDK-managed).
    #[cfg(feature = "debug-capabilities")]
    pub fn debug_types(&self) -> Vec<String> {
        self.debug_repos
            .read()
            .expect("RwLock should not be poisoned")
            .values()
            .map(|repo| repo.name.to_string())
            .collect()
    }

    /// Dev-only: list a repository's values as JSON, addressed by type name.
    /// Values only — the repository API lists values without their keys.
    #[cfg(feature = "debug-capabilities")]
    pub async fn debug_list(&self, type_name: &str) -> Vec<serde_json::Value> {
        match self.debug_repo_named(type_name) {
            Some(repo) => (repo.list)(self).await,
            None => Vec::new(),
        }
    }

    /// Dev-only: read one item by type name and string key, as JSON.
    #[cfg(feature = "debug-capabilities")]
    pub async fn debug_get(&self, type_name: &str, key: &str) -> Option<serde_json::Value> {
        let repo = self.debug_repo_named(type_name)?;
        (repo.get)(self, key).await
    }

    /// Dev-only: write one item by type name and string key. No-ops on an
    /// unknown type, a bad key, or a value that does not deserialize.
    #[cfg(feature = "debug-capabilities")]
    pub async fn debug_set(&self, type_name: &str, key: &str, value: serde_json::Value) {
        if let Some(repo) = self.debug_repo_named(type_name) {
            (repo.set)(self, key, value).await;
        }
    }

    /// Look up the (copyable) shim set for a repository by its type name.
    #[cfg(feature = "debug-capabilities")]
    fn debug_repo_named(&self, type_name: &str) -> Option<DebugRepo> {
        self.debug_repos
            .read()
            .expect("RwLock should not be poisoned")
            .values()
            .find(|repo| repo.name == type_name)
            .copied()
    }

    /// Retrieves a client-managed repository from the map given its type.
    fn get_client_managed<T: RepositoryItem>(&self) -> Option<Arc<dyn Repository<T>>> {
        self.client_managed
            .read()
            .expect("RwLock should not be poisoned")
            .get(&TypeId::of::<T>())
            .and_then(|boxed| boxed.downcast_ref::<Arc<dyn Repository<T>>>())
            .map(Arc::clone)
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
    /// [`DatabaseError::Closed`] on subsequent operations. Client-managed repositories are also
    /// cleared.
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
}

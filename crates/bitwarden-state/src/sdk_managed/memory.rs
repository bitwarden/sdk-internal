use std::{any::TypeId, collections::HashMap, sync::Arc};

use tokio::sync::Mutex;

use crate::{
    repository::{RepositoryItem, RepositoryMigrations},
    sdk_managed::{Database, DatabaseConfiguration, DatabaseError},
};

/// In-memory HashMap-backed implementation of the Database trait.
///
/// Data is ephemeral and will be lost when this instance is dropped (unless
/// cloned — clones share the same backing store via Arc).
/// Intended for testing and development scenarios.
#[derive(Clone)]
pub struct MemoryDatabase(Arc<Mutex<HashMap<TypeId, HashMap<String, String>>>>);

impl MemoryDatabase {
    /// Create a new empty MemoryDatabase.
    pub fn new() -> Self {
        MemoryDatabase(Arc::new(Mutex::new(HashMap::new())))
    }
}

impl Database for MemoryDatabase {
    async fn initialize(
        configuration: DatabaseConfiguration,
        _registrations: RepositoryMigrations,
    ) -> Result<Self, DatabaseError> {
        if !matches!(configuration, DatabaseConfiguration::Memory) {
            return Err(DatabaseError::UnsupportedConfiguration(configuration));
        }
        Ok(Self::new())
    }

    async fn get<T: RepositoryItem>(&self, key: &str) -> Result<Option<T>, DatabaseError> {
        let store = self.0.lock().await;
        match store.get(&TypeId::of::<T>()).and_then(|ns| ns.get(key)) {
            Some(json) => Ok(Some(serde_json::from_str(json)?)),
            None => Ok(None),
        }
    }

    async fn list<T: RepositoryItem>(&self) -> Result<Vec<T>, DatabaseError> {
        let store = self.0.lock().await;
        match store.get(&TypeId::of::<T>()) {
            None => Ok(vec![]),
            Some(ns) => ns
                .values()
                .map(|json| serde_json::from_str(json).map_err(DatabaseError::from))
                .collect(),
        }
    }

    async fn set<T: RepositoryItem>(&self, key: &str, value: T) -> Result<(), DatabaseError> {
        let json = serde_json::to_string(&value)?;
        let mut store = self.0.lock().await;
        store
            .entry(TypeId::of::<T>())
            .or_default()
            .insert(key.to_string(), json);
        Ok(())
    }

    async fn set_bulk<T: RepositoryItem>(
        &self,
        values: Vec<(String, T)>,
    ) -> Result<(), DatabaseError> {
        let mut store = self.0.lock().await;
        let namespace = store.entry(TypeId::of::<T>()).or_default();
        for (key, value) in values {
            let json = serde_json::to_string(&value)?;
            namespace.insert(key, json);
        }
        Ok(())
    }

    async fn remove<T: RepositoryItem>(&self, key: &str) -> Result<(), DatabaseError> {
        let mut store = self.0.lock().await;
        if let Some(namespace) = store.get_mut(&TypeId::of::<T>()) {
            namespace.remove(key);
        }
        Ok(())
    }

    async fn remove_bulk<T: RepositoryItem>(&self, keys: Vec<String>) -> Result<(), DatabaseError> {
        let mut store = self.0.lock().await;
        if let Some(namespace) = store.get_mut(&TypeId::of::<T>()) {
            for key in keys {
                namespace.remove(&key);
            }
        }
        Ok(())
    }

    async fn remove_all<T: RepositoryItem>(&self) -> Result<(), DatabaseError> {
        let mut store = self.0.lock().await;
        store.remove(&TypeId::of::<T>());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::register_repository_item;

    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct TypeA(String);
    register_repository_item!(String => TypeA, "MemTestTypeA");

    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct TypeB(String);
    register_repository_item!(String => TypeB, "MemTestTypeB");

    // MEM-01: Initialize with Memory config succeeds
    #[tokio::test]
    async fn mem_01_initialize_memory_config_succeeds() {
        let result = MemoryDatabase::initialize(
            DatabaseConfiguration::Memory,
            crate::repository::RepositoryMigrations::new(vec![]),
        )
        .await;
        assert!(result.is_ok());
    }

    // MEM-02: Initialize with non-Memory config returns UnsupportedConfiguration
    #[tokio::test]
    async fn mem_02_initialize_wrong_config_fails() {
        use std::path::PathBuf;
        let result = MemoryDatabase::initialize(
            DatabaseConfiguration::Sqlite {
                db_name: "test".to_string(),
                folder_path: PathBuf::from("/tmp"),
            },
            crate::repository::RepositoryMigrations::new(vec![]),
        )
        .await;
        assert!(matches!(
            result,
            Err(DatabaseError::UnsupportedConfiguration(_))
        ));
    }

    // MEM-03: set and get round-trip
    #[tokio::test]
    async fn mem_03_set_get_round_trip() {
        let db = MemoryDatabase::new();
        db.set("k1", TypeA("hello".to_string())).await.unwrap();
        let result = db.get::<TypeA>("k1").await.unwrap();
        assert_eq!(result, Some(TypeA("hello".to_string())));
    }

    // MEM-04: get on missing key returns Ok(None)
    #[tokio::test]
    async fn mem_04_get_missing_key_returns_none() {
        let db = MemoryDatabase::new();
        let result = db.get::<TypeA>("nonexistent").await.unwrap();
        assert_eq!(result, None);
    }

    // MEM-05: list returns all values in namespace
    #[tokio::test]
    async fn mem_05_list_returns_all_values() {
        let db = MemoryDatabase::new();
        db.set("k1", TypeA("a".to_string())).await.unwrap();
        db.set("k2", TypeA("b".to_string())).await.unwrap();
        let mut result = db.list::<TypeA>().await.unwrap();
        result.sort_by_key(|v| v.0.clone());
        assert_eq!(result, vec![TypeA("a".to_string()), TypeA("b".to_string())]);
    }

    // MEM-06: remove deletes key
    #[tokio::test]
    async fn mem_06_remove_deletes_key() {
        let db = MemoryDatabase::new();
        db.set("k1", TypeA("val".to_string())).await.unwrap();
        db.remove::<TypeA>("k1").await.unwrap();
        assert_eq!(db.get::<TypeA>("k1").await.unwrap(), None);
    }

    // MEM-07: remove_bulk deletes multiple keys; remaining key still accessible
    #[tokio::test]
    async fn mem_07_remove_bulk_deletes_multiple_keys() {
        let db = MemoryDatabase::new();
        db.set("k1", TypeA("a".to_string())).await.unwrap();
        db.set("k2", TypeA("b".to_string())).await.unwrap();
        db.set("k3", TypeA("c".to_string())).await.unwrap();
        db.remove_bulk::<TypeA>(vec!["k1".to_string(), "k2".to_string()])
            .await
            .unwrap();
        assert_eq!(db.get::<TypeA>("k1").await.unwrap(), None);
        assert_eq!(db.get::<TypeA>("k2").await.unwrap(), None);
        assert_eq!(
            db.get::<TypeA>("k3").await.unwrap(),
            Some(TypeA("c".to_string()))
        );
    }

    // MEM-08: remove_all clears namespace
    #[tokio::test]
    async fn mem_08_remove_all_clears_namespace() {
        let db = MemoryDatabase::new();
        db.set("k1", TypeA("a".to_string())).await.unwrap();
        db.set("k2", TypeA("b".to_string())).await.unwrap();
        db.remove_all::<TypeA>().await.unwrap();
        assert!(db.list::<TypeA>().await.unwrap().is_empty());
    }

    // MEM-09: set_bulk inserts multiple values
    #[tokio::test]
    async fn mem_09_set_bulk_inserts_multiple() {
        let db = MemoryDatabase::new();
        db.set_bulk(vec![
            ("k1".to_string(), TypeA("a".to_string())),
            ("k2".to_string(), TypeA("b".to_string())),
            ("k3".to_string(), TypeA("c".to_string())),
        ])
        .await
        .unwrap();
        let mut result = db.list::<TypeA>().await.unwrap();
        result.sort_by_key(|v| v.0.clone());
        assert_eq!(
            result,
            vec![
                TypeA("a".to_string()),
                TypeA("b".to_string()),
                TypeA("c".to_string()),
            ]
        );
    }

    // MEM-10: TypeId namespace isolation
    #[tokio::test]
    async fn mem_10_typeid_namespace_isolation() {
        let db = MemoryDatabase::new();
        db.set("shared_key", TypeA("type_a_value".to_string()))
            .await
            .unwrap();
        db.set("shared_key", TypeB("type_b_value".to_string()))
            .await
            .unwrap();
        assert_eq!(
            db.get::<TypeA>("shared_key").await.unwrap(),
            Some(TypeA("type_a_value".to_string()))
        );
        assert_eq!(
            db.get::<TypeB>("shared_key").await.unwrap(),
            Some(TypeB("type_b_value".to_string()))
        );
    }

    // MEM-11: Clone shares backing store
    #[tokio::test]
    async fn mem_11_clone_shares_backing_store() {
        let db = MemoryDatabase::new();
        let clone = db.clone();
        db.set("k1", TypeA("original".to_string())).await.unwrap();
        let result = clone.get::<TypeA>("k1").await.unwrap();
        assert_eq!(result, Some(TypeA("original".to_string())));
    }
}

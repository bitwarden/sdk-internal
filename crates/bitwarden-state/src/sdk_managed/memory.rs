use std::{any::TypeId, collections::HashMap, sync::Arc};

use serde::{Serialize, de::DeserializeOwned};
use tokio::sync::Mutex;

use crate::{
    repository::{RepositoryItem, RepositoryMigrations},
    sdk_managed::{Database, DatabaseConfiguration, DatabaseError},
};

/// In-memory database backend implementing the [`Database`] trait.
///
/// Stores data in process RAM using a [`TypeId`]-keyed nested HashMap.
/// Intended for testing, development, and cross-platform use cases where
/// persistent storage is not required.
///
/// All data is lost when the instance is dropped.
#[derive(Clone)]
pub struct MemoryDatabase(Arc<Mutex<HashMap<TypeId, HashMap<String, String>>>>);

impl MemoryDatabase {
    /// Create a new, empty in-memory database.
    pub fn new() -> Self {
        MemoryDatabase(Arc::new(Mutex::new(HashMap::new())))
    }
}

impl Database for MemoryDatabase {
    async fn initialize(
        _configuration: DatabaseConfiguration,
        _migrations: RepositoryMigrations,
    ) -> Result<Self, DatabaseError> {
        // Memory database requires no I/O or schema initialization.
        // Migrations are intentionally ignored — there is no schema to version.
        Ok(MemoryDatabase::new())
    }

    async fn get<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        key: &str,
    ) -> Result<Option<T>, DatabaseError> {
        let store = self.0.lock().await;
        let type_map = store.get(&TypeId::of::<T>());
        match type_map.and_then(|m| m.get(key)) {
            Some(json) => Ok(Some(serde_json::from_str(json)?)),
            None => Ok(None),
        }
    }

    async fn list<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
    ) -> Result<Vec<T>, DatabaseError> {
        let store = self.0.lock().await;
        match store.get(&TypeId::of::<T>()) {
            None => Ok(vec![]),
            Some(type_map) => {
                let mut results = Vec::with_capacity(type_map.len());
                for json in type_map.values() {
                    results.push(serde_json::from_str(json)?);
                }
                Ok(results)
            }
        }
    }

    async fn set<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        key: &str,
        value: T,
    ) -> Result<(), DatabaseError> {
        let json = serde_json::to_string(&value)?;
        let mut store = self.0.lock().await;
        store
            .entry(TypeId::of::<T>())
            .or_default()
            .insert(key.to_string(), json);
        Ok(())
    }

    async fn set_bulk<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        values: Vec<(String, T)>,
    ) -> Result<(), DatabaseError> {
        let mut store = self.0.lock().await;
        let type_map = store.entry(TypeId::of::<T>()).or_default();
        for (key, value) in values {
            let json = serde_json::to_string(&value)?;
            type_map.insert(key, json);
        }
        Ok(())
    }

    async fn remove<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        key: &str,
    ) -> Result<(), DatabaseError> {
        let mut store = self.0.lock().await;
        if let Some(type_map) = store.get_mut(&TypeId::of::<T>()) {
            type_map.remove(key);
        }
        Ok(())
    }

    async fn remove_bulk<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        keys: Vec<String>,
    ) -> Result<(), DatabaseError> {
        let mut store = self.0.lock().await;
        if let Some(type_map) = store.get_mut(&TypeId::of::<T>()) {
            for key in keys {
                type_map.remove(&key);
            }
        }
        Ok(())
    }

    async fn remove_all<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
    ) -> Result<(), DatabaseError> {
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
    register_repository_item!(String => TypeA, "MemTypeA");

    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct TypeB(u64);
    register_repository_item!(String => TypeB, "MemTypeB");

    #[tokio::test]
    async fn test_memory_database_get_set_remove() {
        let db = MemoryDatabase::new();
        assert_eq!(db.get::<TypeA>("key1").await.unwrap(), None);
        db.set("key1", TypeA("hello".to_string())).await.unwrap();
        assert_eq!(
            db.get::<TypeA>("key1").await.unwrap(),
            Some(TypeA("hello".to_string()))
        );
        db.remove::<TypeA>("key1").await.unwrap();
        assert_eq!(db.get::<TypeA>("key1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_memory_database_type_isolation() {
        let db = MemoryDatabase::new();
        // Same string key for both types — must not interfere
        db.set("key1", TypeA("value_a".to_string())).await.unwrap();
        db.set("key1", TypeB(42)).await.unwrap();
        assert_eq!(
            db.get::<TypeA>("key1").await.unwrap(),
            Some(TypeA("value_a".to_string()))
        );
        assert_eq!(db.get::<TypeB>("key1").await.unwrap(), Some(TypeB(42)));
    }

    #[tokio::test]
    async fn test_memory_database_clone_shares_store() {
        let db1 = MemoryDatabase::new();
        let db2 = db1.clone();
        db1.set("key1", TypeA("shared".to_string())).await.unwrap();
        assert_eq!(
            db2.get::<TypeA>("key1").await.unwrap(),
            Some(TypeA("shared".to_string()))
        );
    }

    #[tokio::test]
    async fn test_memory_database_list() {
        let db = MemoryDatabase::new();
        db.set("a", TypeA("1".to_string())).await.unwrap();
        db.set("b", TypeA("2".to_string())).await.unwrap();
        db.set("c", TypeB(99)).await.unwrap();
        let mut list_a = db.list::<TypeA>().await.unwrap();
        list_a.sort_by_key(|x| x.0.clone());
        assert_eq!(list_a, vec![TypeA("1".to_string()), TypeA("2".to_string())]);
        // TypeB must not appear in TypeA list
        assert_eq!(db.list::<TypeB>().await.unwrap(), vec![TypeB(99)]);
    }

    #[tokio::test]
    async fn test_memory_database_set_bulk() {
        let db = MemoryDatabase::new();
        db.set_bulk(vec![
            ("x".to_string(), TypeA("v1".to_string())),
            ("y".to_string(), TypeA("v2".to_string())),
        ])
        .await
        .unwrap();
        assert_eq!(
            db.get::<TypeA>("x").await.unwrap(),
            Some(TypeA("v1".to_string()))
        );
        assert_eq!(
            db.get::<TypeA>("y").await.unwrap(),
            Some(TypeA("v2".to_string()))
        );
    }

    #[tokio::test]
    async fn test_memory_database_remove_bulk() {
        let db = MemoryDatabase::new();
        db.set("a", TypeA("1".to_string())).await.unwrap();
        db.set("b", TypeA("2".to_string())).await.unwrap();
        db.set("c", TypeA("3".to_string())).await.unwrap();
        db.remove_bulk::<TypeA>(vec!["a".to_string(), "b".to_string()])
            .await
            .unwrap();
        assert_eq!(db.get::<TypeA>("a").await.unwrap(), None);
        assert_eq!(db.get::<TypeA>("b").await.unwrap(), None);
        assert_eq!(
            db.get::<TypeA>("c").await.unwrap(),
            Some(TypeA("3".to_string()))
        );
    }

    #[tokio::test]
    async fn test_memory_database_remove_all() {
        let db = MemoryDatabase::new();
        db.set("a", TypeA("1".to_string())).await.unwrap();
        db.set("b", TypeA("2".to_string())).await.unwrap();
        db.set("z", TypeB(5)).await.unwrap();
        db.remove_all::<TypeA>().await.unwrap();
        assert_eq!(db.list::<TypeA>().await.unwrap(), vec![]);
        // TypeB must be unaffected
        assert_eq!(db.list::<TypeB>().await.unwrap(), vec![TypeB(5)]);
    }

    #[tokio::test]
    async fn test_memory_database_initialize_is_noop() {
        let db = MemoryDatabase::initialize(
            DatabaseConfiguration::Sqlite {
                db_name: "ignored".to_string(),
                folder_path: std::path::PathBuf::from("/tmp"),
            },
            RepositoryMigrations::new(vec![]),
        )
        .await
        .unwrap();
        // initialize returns a fresh, working instance regardless of config
        db.set("k", TypeA("v".to_string())).await.unwrap();
        assert_eq!(
            db.get::<TypeA>("k").await.unwrap(),
            Some(TypeA("v".to_string()))
        );
    }
}

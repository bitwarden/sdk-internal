use std::{
    any::TypeId,
    collections::HashMap,
    sync::{Arc, Mutex},
};

use futures::StreamExt;
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    repository::{RepositoryItem, RepositoryMigrations, RepositoryStream},
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
pub struct MemoryDatabase(Arc<Mutex<Option<Store>>>);

type Store = HashMap<TypeId, HashMap<String, String>>;

impl MemoryDatabase {
    /// Create a new, empty in-memory database.
    pub fn new() -> Self {
        MemoryDatabase(Arc::new(Mutex::new(Some(HashMap::new()))))
    }

    fn with_store<R>(
        &self,
        f: impl FnOnce(&Store) -> Result<R, DatabaseError>,
    ) -> Result<R, DatabaseError> {
        let guard = self.0.lock().expect("Mutex is not poisoned");
        let store = guard.as_ref().ok_or(DatabaseError::Closed)?;
        f(store)
    }

    fn with_store_mut<R>(
        &self,
        f: impl FnOnce(&mut Store) -> Result<R, DatabaseError>,
    ) -> Result<R, DatabaseError> {
        let mut guard = self.0.lock().expect("Mutex is not poisoned");
        let store = guard.as_mut().ok_or(DatabaseError::Closed)?;
        f(store)
    }
}

impl Database for MemoryDatabase {
    async fn initialize(
        configuration: DatabaseConfiguration,
        _migrations: RepositoryMigrations,
    ) -> Result<Self, DatabaseError> {
        let DatabaseConfiguration::Memory = configuration else {
            return Err(DatabaseError::UnsupportedConfiguration(configuration));
        };
        Ok(MemoryDatabase::new())
    }

    async fn get<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        key: &str,
    ) -> Result<Option<T>, DatabaseError> {
        self.with_store(
            |store| match store.get(&TypeId::of::<T>()).and_then(|m| m.get(key)) {
                Some(json) => Ok(Some(serde_json::from_str(json)?)),
                None => Ok(None),
            },
        )
    }

    async fn list<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
    ) -> Result<Vec<T>, DatabaseError> {
        self.with_store(|store| match store.get(&TypeId::of::<T>()) {
            None => Ok(vec![]),
            Some(type_map) => {
                let mut results = Vec::with_capacity(type_map.len());
                for json in type_map.values() {
                    results.push(serde_json::from_str(json)?);
                }
                Ok(results)
            }
        })
    }

    async fn set<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        key: &str,
        value: T,
    ) -> Result<(), DatabaseError> {
        let json = serde_json::to_string(&value)?;
        self.with_store_mut(|store| {
            store
                .entry(TypeId::of::<T>())
                .or_default()
                .insert(key.to_string(), json);
            Ok(())
        })
    }

    async fn set_bulk<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        values: Vec<(String, T)>,
    ) -> Result<(), DatabaseError> {
        self.with_store_mut(|store| {
            let type_map = store.entry(TypeId::of::<T>()).or_default();
            for (key, value) in values {
                let json = serde_json::to_string(&value)?;
                type_map.insert(key, json);
            }
            Ok(())
        })
    }

    async fn remove<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        key: &str,
    ) -> Result<(), DatabaseError> {
        self.with_store_mut(|store| {
            if let Some(type_map) = store.get_mut(&TypeId::of::<T>()) {
                type_map.remove(key);
            }
            Ok(())
        })
    }

    async fn remove_bulk<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
        keys: Vec<String>,
    ) -> Result<(), DatabaseError> {
        self.with_store_mut(|store| {
            if let Some(type_map) = store.get_mut(&TypeId::of::<T>()) {
                for key in keys {
                    type_map.remove(&key);
                }
            }
            Ok(())
        })
    }

    async fn remove_all<T: Serialize + DeserializeOwned + RepositoryItem>(
        &self,
    ) -> Result<(), DatabaseError> {
        self.with_store_mut(|store| {
            store.remove(&TypeId::of::<T>());
            Ok(())
        })
    }

    async fn wipe(&self) -> Result<(), DatabaseError> {
        *self.0.lock().expect("Mutex is not poisoned") = None;
        Ok(())
    }

    /// Reads the keys when first polled, in key order, and deserializes each chunk as it is read.
    /// An item removed in the meantime is skipped.
    fn stream<T: RepositoryItem>(&self, chunk_size: usize) -> RepositoryStream<T> {
        enum Cursor {
            Start,
            Keys(std::vec::IntoIter<String>),
        }

        let db = self.clone();
        let chunk_size = chunk_size.max(1);
        futures::stream::unfold(Some(Cursor::Start), move |cursor| {
            let db = db.clone();
            async move {
                let mut keys = match cursor? {
                    Cursor::Keys(keys) => keys,
                    Cursor::Start => match db.with_store(|store| {
                        let mut keys: Vec<String> = store
                            .get(&TypeId::of::<T>())
                            .map(|items| items.keys().cloned().collect())
                            .unwrap_or_default();
                        keys.sort();
                        Ok(keys)
                    }) {
                        Ok(keys) => keys.into_iter(),
                        Err(error) => return Some((Err(error.into()), None)),
                    },
                };
                let chunk = db.with_store(|store| {
                    let items = store.get(&TypeId::of::<T>());
                    let mut chunk = Vec::with_capacity(chunk_size.min(keys.len()));
                    while chunk.len() < chunk_size {
                        let Some(key) = keys.next() else { break };
                        if let Some(json) = items.and_then(|items| items.get(&key)) {
                            chunk.push(serde_json::from_str(json)?);
                        }
                    }
                    Ok(chunk)
                });
                match chunk {
                    Ok(chunk) if chunk.is_empty() => None,
                    Ok(chunk) => Some((Ok(chunk), Some(Cursor::Keys(keys)))),
                    Err(error) => Some((Err(error.into()), None)),
                }
            }
        })
        .boxed()
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
    async fn test_memory_database_initialize_memory_config() {
        let db = MemoryDatabase::initialize(
            DatabaseConfiguration::Memory,
            RepositoryMigrations::new(vec![]),
        )
        .await
        .unwrap();
        db.set("k", TypeA("v".to_string())).await.unwrap();
        assert_eq!(
            db.get::<TypeA>("k").await.unwrap(),
            Some(TypeA("v".to_string()))
        );
    }

    #[tokio::test]
    async fn test_memory_database_wipe_disconnects_clones() {
        let db = MemoryDatabase::new();
        let clone = db.clone();
        db.set("k", TypeA("v".to_string())).await.unwrap();

        db.wipe().await.unwrap();

        assert!(matches!(
            db.get::<TypeA>("k").await,
            Err(DatabaseError::Closed)
        ));
        assert!(matches!(
            clone.get::<TypeA>("k").await,
            Err(DatabaseError::Closed)
        ));
        assert!(matches!(
            clone.set("k", TypeA("v".to_string())).await,
            Err(DatabaseError::Closed)
        ));
    }

    #[tokio::test]
    async fn test_memory_database_initialize_rejects_non_memory_config() {
        let result = MemoryDatabase::initialize(
            DatabaseConfiguration::Sqlite {
                db_name: "ignored".to_string(),
                folder_path: std::path::PathBuf::from("/tmp"),
            },
            RepositoryMigrations::new(vec![]),
        )
        .await;
        assert!(matches!(
            result,
            Err(DatabaseError::UnsupportedConfiguration(_))
        ));
    }

    async fn stream_a(db: &MemoryDatabase, chunk_size: usize) -> Vec<Vec<TypeA>> {
        use futures::TryStreamExt;
        db.stream::<TypeA>(chunk_size).try_collect().await.unwrap()
    }

    #[tokio::test]
    async fn test_memory_database_stream_in_key_order() {
        let db = MemoryDatabase::new();
        for key in ["c", "a", "e", "b", "d"] {
            db.set(key, TypeA(key.to_string())).await.unwrap();
        }
        db.set("a", TypeB(1)).await.unwrap();

        let chunks = stream_a(&db, 2).await;

        let keys: Vec<Vec<&str>> = chunks
            .iter()
            .map(|chunk| chunk.iter().map(|item| item.0.as_str()).collect())
            .collect();
        assert_eq!(keys, vec![vec!["a", "b"], vec!["c", "d"], vec!["e"]]);
    }

    #[tokio::test]
    async fn test_memory_database_stream_empty_and_oversized() {
        let db = MemoryDatabase::new();
        assert!(stream_a(&db, 2).await.is_empty());

        db.set("a", TypeA("a".to_string())).await.unwrap();
        db.set("b", TypeA("b".to_string())).await.unwrap();
        assert_eq!(stream_a(&db, 10).await.len(), 1);
    }

    #[tokio::test]
    async fn test_memory_database_stream_skips_items_removed_while_reading() {
        use futures::StreamExt;

        let db = MemoryDatabase::new();
        for key in ["a", "b", "c"] {
            db.set(key, TypeA(key.to_string())).await.unwrap();
        }
        let mut stream = db.stream::<TypeA>(1);

        let first = stream.next().await.unwrap().unwrap();
        db.remove::<TypeA>("b").await.unwrap();
        let rest: Vec<_> = stream.map(Result::unwrap).collect().await;

        assert_eq!(first, vec![TypeA("a".to_string())]);
        assert_eq!(rest, vec![vec![TypeA("c".to_string())]]);
    }
}

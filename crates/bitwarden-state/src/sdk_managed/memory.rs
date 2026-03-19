use std::{
    any::TypeId,
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::{
    repository::{RepositoryItem, RepositoryMigrations},
    sdk_managed::{Database, DatabaseConfiguration, DatabaseError},
};

#[derive(Clone)]
pub struct MemoryDatabase(Arc<Mutex<HashMap<TypeId, HashMap<String, String>>>>);

impl MemoryDatabase {
    pub fn new() -> Self {
        MemoryDatabase(Arc::new(Mutex::new(HashMap::new())))
    }

    fn store(&self) -> std::sync::MutexGuard<HashMap<TypeId, HashMap<String, String>>> {
        self.0.lock().expect("MemoryDatabase mutex should not be poisoned")
    }
}

impl Database for MemoryDatabase {
    async fn initialize(
        configuration: DatabaseConfiguration,
        _registrations: RepositoryMigrations,
    ) -> Result<Self, DatabaseError> {
        let DatabaseConfiguration::Memory = configuration else {
            return Err(DatabaseError::UnsupportedConfiguration(configuration));
        };
        Ok(MemoryDatabase::new())
    }

    async fn get<T: RepositoryItem>(
        &self,
        key: &str,
    ) -> Result<Option<T>, DatabaseError> {
        let store = self.store();
        match store.get(&TypeId::of::<T>()).and_then(|ns| ns.get(key)) {
            Some(json) => Ok(Some(serde_json::from_str(json)?)),
            None => Ok(None),
        }
    }

    async fn list<T: RepositoryItem>(
        &self,
    ) -> Result<Vec<T>, DatabaseError> {
        let store = self.store();
        match store.get(&TypeId::of::<T>()) {
            None => Ok(Vec::new()),
            Some(namespace) => namespace
                .values()
                .map(|json| serde_json::from_str(json).map_err(DatabaseError::from))
                .collect(),
        }
    }

    async fn set<T: RepositoryItem>(
        &self,
        key: &str,
        value: T,
    ) -> Result<(), DatabaseError> {
        let json = serde_json::to_string(&value)?;
        self.store().entry(TypeId::of::<T>()).or_default().insert(key.to_string(), json);
        Ok(())
    }

    async fn set_bulk<T: RepositoryItem>(
        &self,
        values: Vec<(String, T)>,
    ) -> Result<(), DatabaseError> {
        let mut store = self.store();
        let namespace = store.entry(TypeId::of::<T>()).or_default();
        for (key, value) in values {
            namespace.insert(key, serde_json::to_string(&value)?);
        }
        Ok(())
    }

    async fn remove<T: RepositoryItem>(
        &self,
        key: &str,
    ) -> Result<(), DatabaseError> {
        if let Some(namespace) = self.store().get_mut(&TypeId::of::<T>()) {
            namespace.remove(key);
        }
        Ok(())
    }

    async fn remove_bulk<T: RepositoryItem>(
        &self,
        keys: Vec<String>,
    ) -> Result<(), DatabaseError> {
        if let Some(namespace) = self.store().get_mut(&TypeId::of::<T>()) {
            for key in &keys {
                namespace.remove(key.as_str());
            }
        }
        Ok(())
    }

    async fn remove_all<T: RepositoryItem>(
        &self,
    ) -> Result<(), DatabaseError> {
        self.store().remove(&TypeId::of::<T>());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::register_repository_item;

    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct ItemA(String);
    register_repository_item!(String => ItemA, "ItemA");

    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct ItemB(u32);
    register_repository_item!(String => ItemB, "ItemB");

    fn make_db() -> MemoryDatabase { MemoryDatabase::new() }

    #[tokio::test]
    async fn mem_01_initialize_memory_config_succeeds() {
        let result = MemoryDatabase::initialize(
            DatabaseConfiguration::Memory,
            crate::repository::RepositoryMigrations::new(vec![]),
        ).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn mem_02_initialize_non_memory_config_fails() {
        let result = MemoryDatabase::initialize(
            DatabaseConfiguration::Sqlite { db_name: "test".to_string(), folder_path: "/tmp".into() },
            crate::repository::RepositoryMigrations::new(vec![]),
        ).await;
        assert!(matches!(result, Err(DatabaseError::UnsupportedConfiguration(_))));
    }

    #[tokio::test]
    async fn mem_03_set_get_round_trip() {
        let db = make_db();
        db.set::<ItemA>("k1", ItemA("hello".to_string())).await.unwrap();
        assert_eq!(db.get::<ItemA>("k1").await.unwrap(), Some(ItemA("hello".to_string())));
    }

    #[tokio::test]
    async fn mem_04_get_missing_key_returns_none() {
        let db = make_db();
        assert_eq!(db.get::<ItemA>("nope").await.unwrap(), None);
    }

    #[tokio::test]
    async fn mem_05_list_returns_all_values() {
        let db = make_db();
        db.set::<ItemA>("k1", ItemA("a".to_string())).await.unwrap();
        db.set::<ItemA>("k2", ItemA("b".to_string())).await.unwrap();
        let mut list = db.list::<ItemA>().await.unwrap();
        list.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(list, vec![ItemA("a".to_string()), ItemA("b".to_string())]);
    }

    #[tokio::test]
    async fn mem_06_remove_deletes_key() {
        let db = make_db();
        db.set::<ItemA>("k1", ItemA("hello".to_string())).await.unwrap();
        db.remove::<ItemA>("k1").await.unwrap();
        assert_eq!(db.get::<ItemA>("k1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn mem_07_remove_bulk_deletes_multiple_keys() {
        let db = make_db();
        db.set::<ItemA>("k1", ItemA("a".to_string())).await.unwrap();
        db.set::<ItemA>("k2", ItemA("b".to_string())).await.unwrap();
        db.set::<ItemA>("k3", ItemA("c".to_string())).await.unwrap();
        db.remove_bulk::<ItemA>(vec!["k1".to_string(), "k2".to_string()]).await.unwrap();
        assert_eq!(db.get::<ItemA>("k1").await.unwrap(), None);
        assert_eq!(db.get::<ItemA>("k2").await.unwrap(), None);
        assert_eq!(db.get::<ItemA>("k3").await.unwrap(), Some(ItemA("c".to_string())));
    }

    #[tokio::test]
    async fn mem_08_remove_all_clears_namespace() {
        let db = make_db();
        db.set::<ItemA>("k1", ItemA("a".to_string())).await.unwrap();
        db.remove_all::<ItemA>().await.unwrap();
        assert_eq!(db.list::<ItemA>().await.unwrap(), vec![]);
    }

    #[tokio::test]
    async fn mem_09_set_bulk_inserts_multiple_values() {
        let db = make_db();
        db.set_bulk::<ItemA>(vec![
            ("k1".to_string(), ItemA("a".to_string())),
            ("k2".to_string(), ItemA("b".to_string())),
            ("k3".to_string(), ItemA("c".to_string())),
        ]).await.unwrap();
        assert_eq!(db.list::<ItemA>().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn mem_10_typeid_namespace_isolation() {
        let db = make_db();
        db.set::<ItemA>("shared_key", ItemA("from_a".to_string())).await.unwrap();
        db.set::<ItemB>("shared_key", ItemB(42)).await.unwrap();
        assert_eq!(db.get::<ItemA>("shared_key").await.unwrap(), Some(ItemA("from_a".to_string())));
        assert_eq!(db.get::<ItemB>("shared_key").await.unwrap(), Some(ItemB(42)));
    }

    #[tokio::test]
    async fn mem_11_clone_shares_backing_store() {
        let db = make_db();
        let cloned = db.clone();
        db.set::<ItemA>("k1", ItemA("original".to_string())).await.unwrap();
        assert_eq!(cloned.get::<ItemA>("k1").await.unwrap(), Some(ItemA("original".to_string())));
    }
}

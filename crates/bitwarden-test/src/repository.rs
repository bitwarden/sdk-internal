use bitwarden_state::repository::{Repository, RepositoryError, RepositoryItem};

/// A simple in-memory repository implementation. The data is only stored in memory and will not
/// persist beyond the lifetime of the repository instance.
///
/// Primary use case is for unit and integration tests.
pub struct MemoryRepository<V: RepositoryItem> {
    store: std::sync::Mutex<std::collections::HashMap<String, V>>,
}

impl<V: RepositoryItem + Clone> Default for MemoryRepository<V> {
    fn default() -> Self {
        Self {
            store: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl<V: RepositoryItem + Clone> Repository<V> for MemoryRepository<V> {
    async fn get(&self, key: V::Key) -> Result<Option<V>, RepositoryError> {
        let store = self
            .store
            .lock()
            .map_err(|e| RepositoryError::Internal(e.to_string()))?;
        let key = key.to_string();
        Ok(store.get(&key).cloned())
    }

    async fn list(&self) -> Result<Vec<V>, RepositoryError> {
        let store = self
            .store
            .lock()
            .map_err(|e| RepositoryError::Internal(e.to_string()))?;
        Ok(store.values().cloned().collect())
    }

    async fn set(&self, key: V::Key, value: V) -> Result<(), RepositoryError> {
        let mut store = self
            .store
            .lock()
            .map_err(|e| RepositoryError::Internal(e.to_string()))?;
        let key = key.to_string();
        store.insert(key, value);
        Ok(())
    }

    async fn set_bulk(&self, values: Vec<(V::Key, V)>) -> Result<(), RepositoryError> {
        let mut store = self
            .store
            .lock()
            .map_err(|e| RepositoryError::Internal(e.to_string()))?;
        for (key, value) in values {
            store.insert(key.to_string(), value);
        }
        Ok(())
    }

    async fn remove(&self, key: V::Key) -> Result<(), RepositoryError> {
        let mut store = self
            .store
            .lock()
            .map_err(|e| RepositoryError::Internal(e.to_string()))?;
        let key = key.to_string();
        store.remove(&key);
        Ok(())
    }

    async fn remove_bulk(&self, keys: Vec<V::Key>) -> Result<(), RepositoryError> {
        let mut store = self
            .store
            .lock()
            .map_err(|e| RepositoryError::Internal(e.to_string()))?;
        for key in keys {
            store.remove(&key.to_string());
        }
        Ok(())
    }

    async fn remove_all(&self) -> Result<(), RepositoryError> {
        let mut store = self
            .store
            .lock()
            .map_err(|e| RepositoryError::Internal(e.to_string()))?;
        store.clear();
        Ok(())
    }
}

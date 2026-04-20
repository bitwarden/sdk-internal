use bitwarden_state::{
    repository::RepositoryError,
    value::{Value, ValueItem},
};

/// A simple in-memory single-value store. The data is only stored in memory and will not
/// persist beyond the lifetime of the instance.
///
/// Primary use case is for unit and integration tests.
pub struct MemoryValue<V: ValueItem> {
    store: std::sync::Mutex<Option<V>>,
}

impl<V: ValueItem + Clone> Default for MemoryValue<V> {
    fn default() -> Self {
        Self {
            store: std::sync::Mutex::new(None),
        }
    }
}

#[async_trait::async_trait]
impl<V: ValueItem + Clone> Value<V> for MemoryValue<V> {
    async fn get(&self) -> Result<Option<V>, RepositoryError> {
        let store = self
            .store
            .lock()
            .map_err(|e| RepositoryError::Internal(e.to_string()))?;
        Ok(store.clone())
    }

    async fn set(&self, value: V) -> Result<(), RepositoryError> {
        let mut store = self
            .store
            .lock()
            .map_err(|e| RepositoryError::Internal(e.to_string()))?;
        *store = Some(value);
        Ok(())
    }

    async fn remove(&self) -> Result<(), RepositoryError> {
        let mut store = self
            .store
            .lock()
            .map_err(|e| RepositoryError::Internal(e.to_string()))?;
        *store = None;
        Ok(())
    }
}

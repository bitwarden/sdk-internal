use std::sync::{Arc, Mutex};

use bitwarden_state::{
    Persist, PersistedValue, PersistedValueError, PersistedValueKey, PersistedValueTrait,
};

/// A simple in-memory persisted value backend. The data is only stored in memory and will not
/// persist beyond the lifetime of the backend instance.
///
/// Primary use case is for unit and integration tests.
pub struct MemoryPersistedValue<T> {
    value: Mutex<Option<T>>,
}

impl<T: Clone + Persist> MemoryPersistedValue<T> {
    /// Create a persisted value handle backed by a fresh in-memory store.
    pub fn create<K: PersistedValueKey<Value = T>>() -> PersistedValue<K> {
        PersistedValue::new(Arc::new(Self {
            value: Mutex::new(None),
        }))
    }
}

#[async_trait::async_trait]
impl<T: Clone + Persist> PersistedValueTrait<T> for MemoryPersistedValue<T> {
    async fn get(&self) -> Result<Option<T>, PersistedValueError> {
        Ok(self.value.lock().expect("Mutex is not poisoned").clone())
    }

    async fn set(&self, value: T) -> Result<(), PersistedValueError> {
        *self.value.lock().expect("Mutex is not poisoned") = Some(value);
        Ok(())
    }

    async fn remove(&self) -> Result<(), PersistedValueError> {
        *self.value.lock().expect("Mutex is not poisoned") = None;
        Ok(())
    }
}

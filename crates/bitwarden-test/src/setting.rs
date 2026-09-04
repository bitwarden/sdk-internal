use std::sync::{Arc, Mutex};

use bitwarden_state::{PersistentValue, Setting, SettingTrait, SettingsError};

/// A simple in-memory setting backend. The data is only stored in memory and will not persist
/// beyond the lifetime of the backend instance.
///
/// Primary use case is for unit and integration tests.
pub struct MemorySetting<T> {
    value: Mutex<Option<T>>,
}

impl<T: Clone + PersistentValue> MemorySetting<T> {
    /// Create a setting handle backed by a fresh in-memory store.
    pub fn create() -> Setting<T> {
        Setting::new(Arc::new(Self {
            value: Mutex::new(None),
        }))
    }
}

#[async_trait::async_trait]
impl<T: Clone + PersistentValue> SettingTrait<T> for MemorySetting<T> {
    async fn get(&self) -> Result<Option<T>, SettingsError> {
        Ok(self.value.lock().expect("Mutex is not poisoned").clone())
    }

    async fn set(&self, value: T) -> Result<(), SettingsError> {
        *self.value.lock().expect("Mutex is not poisoned") = Some(value);
        Ok(())
    }

    async fn remove(&self) -> Result<(), SettingsError> {
        *self.value.lock().expect("Mutex is not poisoned") = None;
        Ok(())
    }
}

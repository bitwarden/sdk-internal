//! The legacy [`Setting`] handle.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::{Key, ValueError, ValueItem};
use crate::repository::RepositoryTrait;

/// A handle to a single value in storage, addressed by a [`Key`] passed at runtime.
///
/// Superseded by [`Value`](crate::Value), which is addressed by a marker type and so can be
/// injected with `#[derive(FromClient)]`. Removed once every caller has migrated.
///
/// # Example
/// ```rust,ignore
/// use bitwarden_state::register_setting_key;
///
/// register_setting_key!(const THEME: String = "theme");
///
/// let setting = client.platform().state().setting(THEME)?;
///
/// // Get the current value
/// let value: Option<String> = setting.get().await?;
///
/// // Update the value
/// setting.update("dark".to_string()).await?;
///
/// // Delete the value
/// setting.delete().await?;
/// ```
#[derive(Clone)]
pub struct Setting<T> {
    storage: Arc<dyn RepositoryTrait<ValueItem>>,
    key: Key<T>,
}

impl<T> Setting<T> {
    /// Create a new setting handle from a storage handle and key.
    pub fn new(storage: Arc<dyn RepositoryTrait<ValueItem>>, key: Key<T>) -> Self {
        Self { storage, key }
    }

    /// Get the current value of this setting.
    ///
    /// Returns `None` if the setting doesn't exist in storage.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails, which may indicate:
    /// - Schema evolution problems (type definition changed)
    /// - Data corruption
    /// - Type mismatch (wrong `Key<T>` type for stored data)
    pub async fn get(&self) -> Result<Option<T>, ValueError>
    where
        T: for<'de> Deserialize<'de>,
    {
        match self.storage.get(self.key.name.to_string()).await? {
            Some(item) => Ok(Some(serde_json::from_value::<T>(item.0)?)),
            None => Ok(None),
        }
    }

    /// Update (or create) this setting with a new value.
    pub async fn update(&self, value: T) -> Result<(), ValueError>
    where
        T: Serialize,
    {
        let item = ValueItem(serde_json::to_value(&value)?);

        self.storage.set(self.key.name.to_string(), item).await?;

        Ok(())
    }

    /// Delete this setting from storage.
    pub async fn delete(&self) -> Result<(), ValueError> {
        self.storage.remove(self.key.name.to_string()).await?;

        Ok(())
    }
}

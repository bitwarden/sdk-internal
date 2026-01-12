//! Setting types for type-safe access to individual settings.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::Key;
use crate::{
    registry::StateRegistryError,
    repository::{Repository, RepositoryError},
};

/// Internal setting value stored in the settings repository.
///
/// This type wraps a JSON value for flexible storage. Users should not work with
/// this type directly - use the [`Setting<T>`] handle via `StateClient::setting()` instead,
/// which provides type-safe access.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SettingItem(pub(crate) serde_json::Value);

// Register SettingItem for repository usage
crate::register_repository_item!(SettingItem, "Setting");

/// A handle to a single setting value in storage.
///
/// This type provides async methods to get, update, and delete the setting value.
/// Obtained via [`StateClient::setting()`](crate::platform::StateClient::setting).
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
pub struct Setting<T> {
    repository: Arc<dyn Repository<SettingItem>>,
    key: Key<T>,
}

impl<T> Setting<T> {
    /// Create a new setting handle from a repository and key.
    pub fn new(repository: Arc<dyn Repository<SettingItem>>, key: Key<T>) -> Self {
        Self { repository, key }
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
    pub async fn get(&self) -> Result<Option<T>, SettingsError>
    where
        T: for<'de> Deserialize<'de>,
    {
        match self.repository.get(self.key.name.to_string()).await? {
            Some(item) => Ok(Some(serde_json::from_value::<T>(item.0)?)),
            None => Ok(None),
        }
    }

    /// Update (or create) this setting with a new value.
    pub async fn update(&self, value: T) -> Result<(), SettingsError>
    where
        T: Serialize,
    {
        let json_value = serde_json::to_value(&value)?;
        let item = SettingItem(json_value);

        self.repository.set(self.key.name.to_string(), item).await?;

        Ok(())
    }

    /// Delete this setting from storage.
    pub async fn delete(&self) -> Result<(), SettingsError> {
        self.repository.remove(self.key.name.to_string()).await?;

        Ok(())
    }
}

/// Errors that can occur when working with settings.
#[derive(Debug, Error)]
pub enum SettingsError {
    /// Failed to serialize/deserialize setting value
    #[error("Failed to serialize/deserialize setting: {0}")]
    Json(#[from] serde_json::Error),
    /// Repository operation failed
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    /// State registry operation failed
    #[error(transparent)]
    Registry(#[from] StateRegistryError),
}

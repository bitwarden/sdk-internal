//! Setting types for type-safe access to individual settings.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    persistent_value::PersistentValue, registry::StateRegistryError, sdk_managed::DatabaseError,
};

/// Internal setting value as stored in the SDK-managed database.
///
/// This type wraps a JSON value for flexible storage. Users should not work with
/// this type directly - use the [`Setting<T>`] handle via `StateClient::setting()` instead,
/// which provides type-safe access.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SettingItem(pub(crate) serde_json::Value);

crate::register_repository_item!(String => SettingItem, "Setting");

#[doc(hidden)]
#[async_trait::async_trait]
pub trait SettingTrait<T: PersistentValue>: Send + Sync {
    async fn get(&self) -> Result<Option<T>, SettingsError>;
    async fn set(&self, value: T) -> Result<(), SettingsError>;
    async fn remove(&self) -> Result<(), SettingsError>;
}

/// A handle to a single setting value in storage.
///
/// This type provides async methods to get, update, and delete the setting value.
/// Obtained via `StateClient::setting()`.
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
pub struct Setting<T: PersistentValue> {
    backend: Arc<dyn SettingTrait<T>>,
}

impl<T: PersistentValue> Setting<T> {
    /// Create a new setting handle from a backend.
    ///
    /// The backend is already bound to a single key, so it decides where the value is stored.
    pub fn new(backend: Arc<dyn SettingTrait<T>>) -> Self {
        Self { backend }
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
    pub async fn get(&self) -> Result<Option<T>, SettingsError> {
        self.backend.get().await
    }

    /// Update (or create) this setting with a new value.
    pub async fn update(&self, value: T) -> Result<(), SettingsError> {
        self.backend.set(value).await
    }

    /// Delete this setting from storage.
    pub async fn delete(&self) -> Result<(), SettingsError> {
        self.backend.remove().await
    }
}

/// Errors that can occur when working with settings.
#[derive(Debug, Error)]
pub enum SettingsError {
    /// Failed to serialize/deserialize setting value
    #[error("Failed to serialize/deserialize setting: {0}")]
    Json(#[from] serde_json::Error),
    /// Database operation failed
    #[error(transparent)]
    Database(#[from] DatabaseError),
    /// State registry operation failed
    #[error(transparent)]
    Registry(#[from] StateRegistryError),
}

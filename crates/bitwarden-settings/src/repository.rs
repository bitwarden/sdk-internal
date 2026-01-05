//! High-level settings repository API.

use bitwarden_core::Client;
use bitwarden_state::{
    registry::StateRegistryError,
    repository::{Repository, RepositoryError},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;

use crate::{Key, Setting};

/// High-level API for settings storage.
///
/// Handles serialization internally - users work directly with their types.
/// Access this via the [`ClientSettingsExt`] trait on [`Client`].
///
/// # Example
/// ```rust,no_run
/// use bitwarden_settings::{ClientSettingsExt, Key};
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct Config {
///     theme: String,
/// }
///
/// const CONFIG: Key<Config> = Key::new("config");
///
/// # async {
/// # let client: bitwarden_core::Client = todo!();
/// // Get value
/// let config: Option<Config> = client.settings().get(CONFIG).await?;
///
/// // Set value
/// client.settings().set(CONFIG, Config {
///     theme: "dark".to_string(),
/// }).await?;
///
/// // Remove value
/// client.settings().remove(CONFIG).await?;
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// # };
/// ```
pub struct SettingsRepository<'a> {
    client: &'a Client,
}

impl<'a> SettingsRepository<'a> {
    /// Create a new settings repository for the given client.
    ///
    /// Typically accessed via [`ClientSettingsExt::settings()`] instead of calling directly.
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Get a value using a type-safe key.
    ///
    /// Returns `None` if the key doesn't exist or if deserialization fails.
    /// Deserialization errors are logged but do not propagate.
    ///
    /// # Example
    /// ```rust,no_run
    /// use bitwarden_settings::{ClientSettingsExt, Key};
    ///
    /// const THEME: Key<String> = Key::new("theme");
    ///
    /// # async {
    /// # let client: bitwarden_core::Client = todo!();
    /// let theme: Option<String> = client.settings().get(THEME).await?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// # };
    /// ```
    pub async fn get<T: for<'de> Deserialize<'de>>(
        &self,
        key: Key<T>,
    ) -> Result<Option<T>, SettingsError> {
        match self
            .client
            .platform()
            .state()
            .get_sdk_managed::<Setting>()?
            .get(key.name().to_string())
            .await?
        {
            Some(setting) => match serde_json::from_value::<T>(setting.0) {
                Ok(value) => Ok(Some(value)),
                Err(e) => {
                    warn!("Failed to deserialize setting '{}': {:?}", key.name(), e);
                    Ok(None)
                }
            },
            None => Ok(None),
        }
    }

    /// Set a value using a type-safe key.
    ///
    /// # Example
    /// ```rust,no_run
    /// use bitwarden_settings::{ClientSettingsExt, Key};
    ///
    /// const THEME: Key<String> = Key::new("theme");
    ///
    /// # async {
    /// # let client: bitwarden_core::Client = todo!();
    /// client.settings().set(THEME, "dark".to_string()).await?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// # };
    /// ```
    pub async fn set<T: Serialize>(&self, key: Key<T>, value: T) -> Result<(), SettingsError> {
        let json_value = serde_json::to_value(&value)?;
        let setting = Setting(json_value);

        self.client
            .platform()
            .state()
            .get_sdk_managed::<Setting>()?
            .set(key.name().to_string(), setting)
            .await?;
        Ok(())
    }

    /// Remove a value using a type-safe key.
    ///
    /// # Example
    /// ```rust,no_run
    /// use bitwarden_settings::{ClientSettingsExt, Key};
    ///
    /// const THEME: Key<String> = Key::new("theme");
    ///
    /// # async {
    /// # let client: bitwarden_core::Client = todo!();
    /// client.settings().remove(THEME).await?;
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// # };
    /// ```
    pub async fn remove<T>(&self, key: Key<T>) -> Result<(), SettingsError> {
        self.client
            .platform()
            .state()
            .get_sdk_managed::<Setting>()?
            .remove(key.name().to_string())
            .await?;
        Ok(())
    }
}

/// Extension trait to get [`SettingsRepository`] from [`Client`].
///
/// # Example
/// ```rust,no_run
/// use bitwarden_settings::{ClientSettingsExt, Key};
///
/// const THEME: Key<String> = Key::new("theme");
///
/// # async {
/// # let client: bitwarden_core::Client = todo!();
/// let settings = client.settings();
/// let theme: Option<String> = settings.get(THEME).await?;
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// # };
/// ```
pub trait ClientSettingsExt {
    /// Get a settings repository for this client.
    fn settings(&self) -> SettingsRepository<'_>;
}

impl ClientSettingsExt for Client {
    fn settings(&self) -> SettingsRepository<'_> {
        SettingsRepository::new(self)
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

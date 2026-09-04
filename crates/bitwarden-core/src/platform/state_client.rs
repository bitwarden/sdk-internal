use std::sync::Arc;

use bitwarden_state::{
    Key, Setting, SettingItem, SettingsError,
    registry::StateRegistryError,
    repository::{RepositoryItem, RepositoryTrait},
};

use crate::Client;

/// Wrapper for state specific functionality.
pub struct StateClient {
    pub(crate) client: Client,
}

impl StateClient {
    /// Register a client managed state repository for a specific type.
    pub fn register_client_managed<T: 'static + RepositoryTrait<V>, V: RepositoryItem>(
        &self,
        store: Arc<T>,
    ) {
        self.client
            .internal
            .state_registry
            .register_client_managed(store)
    }

    /// Get a handle to the repository storing items of type `T`, preferring a client-managed
    /// repository and falling back to SDK-managed storage.
    pub fn repo<T: RepositoryItem>(&self) -> bitwarden_state::Repository<T> {
        self.client.internal.state_registry.repo::<T>()
    }

    /// Get a repository with fallback: prefer client-managed, fall back to SDK-managed.
    ///
    /// Superseded by [`Self::repo`]. Removed once callers have migrated.
    ///
    /// # Errors
    /// This method never fails, but returns a Result for backwards compatibility.
    pub fn get<T>(&self) -> Result<Arc<dyn RepositoryTrait<T>>, StateRegistryError>
    where
        T: RepositoryItem,
    {
        self.client.internal.state_registry.get()
    }

    /// Get a handle to a setting by its type-safe key.
    ///
    /// Returns a [`Setting`] handle that can be used to get, update, or delete the value.
    ///
    /// # Example
    /// ```rust
    /// use bitwarden_state::register_setting_key;
    /// use serde::{Deserialize, Serialize};
    ///
    /// #[derive(Serialize, Deserialize)]
    /// struct AppConfig {
    ///     theme: String,
    /// }
    ///
    /// register_setting_key!(const CONFIG: AppConfig = "app_config");
    ///
    /// # async fn example(client: bitwarden_core::Client) -> Result<(), bitwarden_state::SettingsError> {
    /// let setting = client.platform().state().setting(CONFIG)?;
    /// let value: Option<AppConfig> = setting.get().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn setting<T>(&self, key: Key<T>) -> Result<Setting<T>, SettingsError> {
        let repository = self.client.internal.state_registry.get::<SettingItem>()?;
        Ok(Setting::new(repository, key))
    }
}

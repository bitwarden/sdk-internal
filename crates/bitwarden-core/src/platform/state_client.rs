use std::sync::Arc;

use bitwarden_state::{
    Key, Setting, SettingsError, Value, ValueKey,
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

    /// Get a handle to the value identified by `K`.
    ///
    /// Returns a [`Value`] handle that can be used to read, write, or remove the value.
    ///
    /// # Example
    /// ```rust
    /// use bitwarden_state::register_value_key;
    /// use serde::{Deserialize, Serialize};
    ///
    /// #[derive(Serialize, Deserialize)]
    /// pub struct AppConfig {
    ///     theme: String,
    /// }
    ///
    /// register_value_key!(CONFIG: AppConfig = "app_config");
    ///
    /// # async fn example(client: bitwarden_core::Client) -> Result<(), bitwarden_state::ValueError> {
    /// let config = client.platform().state().value::<CONFIG>();
    /// let value: Option<AppConfig> = config.get_opt().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn value<K: ValueKey>(&self) -> Value<K> {
        self.client.internal.state_registry.value::<K>()
    }

    /// Get a handle to a setting by its type-safe key.
    ///
    /// Superseded by [`Self::value`]. Removed once callers have migrated.
    ///
    /// # Errors
    /// This method never fails, but returns a Result for backwards compatibility.
    pub fn setting<T>(&self, key: Key<T>) -> Result<Setting<T>, SettingsError> {
        Ok(self.client.internal.state_registry.setting(key)?)
    }
}

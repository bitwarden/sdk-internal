use std::sync::Arc;

use bitwarden_state::{
    DatabaseConfiguration, Key, Setting, SettingItem, SettingsError, Value, ValueItem,
    registry::StateRegistryError,
    repository::{Repository, RepositoryItem, RepositoryMigrations},
};

use crate::Client;

/// Wrapper for state specific functionality.
pub struct StateClient {
    pub(crate) client: Client,
}

impl StateClient {
    /// Register a client managed state repository for a specific type.
    pub fn register_client_managed<T: 'static + Repository<V>, V: RepositoryItem>(
        &self,
        store: Arc<T>,
    ) {
        self.client
            .internal
            .state_registry
            .register_client_managed(store)
    }

    /// Initialize the database for SDK managed repositories.
    pub async fn initialize_database(
        &self,
        configuration: DatabaseConfiguration,
        migrations: RepositoryMigrations,
    ) -> Result<(), StateRegistryError> {
        self.client
            .internal
            .state_registry
            .initialize_database(configuration, migrations)
            .await
    }

    /// Get a repository with fallback: prefer client-managed, fall back to SDK-managed.
    ///
    /// This method first attempts to retrieve a client-managed repository. If not registered,
    /// it falls back to an SDK-managed repository. Both are returned as `Arc<dyn Repository<T>>`.
    ///
    /// # Errors
    /// Returns `StateRegistryError` when neither repository type is available.
    pub fn get<T>(&self) -> Result<Arc<dyn Repository<T>>, StateRegistryError>
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

    /// Register a client-managed single-value state store for a specific type.
    pub fn register_client_managed_value<T: 'static + Value<V>, V: ValueItem>(
        &self,
        store: Arc<T>,
    ) {
        self.client
            .internal
            .state_registry
            .register_client_managed_value(store)
    }

    /// Retrieve a client-managed single-value state store for a specific type.
    ///
    /// # Errors
    /// Returns `StateRegistryError::ValueNotRegistered` if no store has been registered for `V`.
    pub fn get_value<V: ValueItem>(&self) -> Result<Arc<dyn Value<V>>, StateRegistryError> {
        self.client.internal.state_registry.get_value()
    }
}

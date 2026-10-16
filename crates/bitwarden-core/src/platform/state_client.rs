use std::sync::Arc;

use bitwarden_state::{
    PersistedValue, PersistedValueKey,
    registry::StateRegistryError,
    repository::{Repository, RepositoryItem},
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

    /// Get a handle to a persisted value by its type-safe key.
    ///
    /// Returns a [`PersistedValue`] handle that can be used to get, update, or delete the value.
    ///
    /// # Example
    /// ```rust
    /// use bitwarden_state::register_persisted_value;
    /// use serde::{Deserialize, Serialize};
    ///
    /// #[derive(Serialize, Deserialize)]
    /// struct AppConfig {
    ///     theme: String,
    /// }
    ///
    /// register_persisted_value!(CONFIG: AppConfig = "app_config");
    ///
    /// # async fn example(client: bitwarden_core::Client) -> Result<(), bitwarden_state::PersistedValueError> {
    /// let value = client.platform().state().value::<CONFIG>();
    /// let config: Option<AppConfig> = value.try_get().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn value<K: PersistedValueKey>(&self) -> PersistedValue<K> {
        self.client.internal.state_registry.value::<K>()
    }
}

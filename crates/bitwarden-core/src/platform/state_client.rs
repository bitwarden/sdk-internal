use std::sync::Arc;

use bitwarden_state::{
    DatabaseConfiguration,
    registry::{RepositoryNotFoundError, StateRegistryError},
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
            .repository_map
            .register_client_managed(store)
    }

    /// Get a client managed state repository for a specific type, if it exists.
    pub fn get_client_managed<T: RepositoryItem>(
        &self,
    ) -> Result<Arc<dyn Repository<T>>, RepositoryNotFoundError> {
        self.client.internal.repository_map.get_client_managed()
    }

    /// Initialize the database for SDK managed repositories.
    pub async fn initialize_database(
        &self,
        configuration: DatabaseConfiguration,
        migrations: RepositoryMigrations,
    ) -> Result<(), StateRegistryError> {
        self.client
            .internal
            .repository_map
            .initialize_database(configuration, migrations)
            .await
    }

    /// Get a SDK managed state repository for a specific type, if it exists.
    pub fn get_sdk_managed<T: RepositoryItem>(
        &self,
    ) -> Result<Arc<dyn Repository<T>>, StateRegistryError> {
        self.client.internal.repository_map.get_sdk_managed()
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
        self.client.internal.repository_map.get()
    }
}

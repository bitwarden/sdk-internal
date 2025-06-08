use std::sync::Arc;

use bitwarden_state::{
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
    ) -> Result<(), StateRegistryError> {
        self.client
            .internal
            .repository_map
            .write()
            .expect("RwLock is not poisoned")
            .register_client_managed(store)
    }

    /// Get a client managed state repository for a specific type, if it exists.
    pub fn get_client_managed<T: RepositoryItem>(&self) -> Option<Arc<dyn Repository<T>>> {
        self.client
            .internal
            .repository_map
            .read()
            .expect("RwLock is not poisoned")
            .get_client_managed()
    }
}

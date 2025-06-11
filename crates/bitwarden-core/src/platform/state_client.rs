use std::sync::Arc;

use bitwarden_state::repository::{Repository, RepositoryItem};

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
    pub fn get_client_managed<T: RepositoryItem>(&self) -> Option<Arc<dyn Repository<T>>> {
        self.client.internal.repository_map.get_client_managed()
    }
}

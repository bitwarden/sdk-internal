use std::sync::Arc;

use bitwarden_state::repository::Repository;

use crate::Client;

/// Wrapper for state specific functionality.
pub struct StateClient {
    pub(crate) client: Client,
}

impl StateClient {
    /// Register a client managed state repository for a specific type.
    pub fn register_repository<T: 'static + Repository<V>, V: 'static>(&self, store: Arc<T>) {
        self.client
            .internal
            .repository_map
            .write()
            .expect("RwLock is not poisoned")
            .insert(store);
    }

    /// Get a client managed state repository for a specific type, if it exists.
    pub fn get_repository<T: 'static>(&self) -> Option<Arc<dyn Repository<T>>> {
        self.client
            .internal
            .repository_map
            .read()
            .expect("RwLock is not poisoned")
            .get()
    }
}

use std::sync::Arc;

use crate::backend::ClientManagerBackend;

pub struct ClientManager {
    internal: Arc<InternalClientManager>,
}

pub struct InternalClientManager {
    backend: Box<dyn ClientManagerBackend>,
}

impl ClientManager {
    pub fn new(backend: Box<dyn ClientManagerBackend>) -> Self {
        Self {
            internal: Arc::new(InternalClientManager { backend }),
        }
    }

    pub async fn get_client(&self, client_id: &str) -> Option<bitwarden_core::Client> {
        self.internal.backend.get_client(client_id).await
    }

    pub async fn set_client(&self, client: bitwarden_core::Client) {
        self.internal.backend.set_client(client).await;
    }

    pub async fn delete_client(&self, client_id: &str) {
        self.internal.backend.delete_client(client_id).await;
    }
}

use std::sync::Arc;

use bitwarden_core::UserId;

use crate::backend::{ClientHasNoUserIdError, ClientManagerBackend};

/// Manages multiple clients for the Bitwarden SDK, allowing for multiple accounts to be used in the
/// same application. Think "account switching" but for the SDK.
pub struct ClientManager {
    internal: Arc<InternalClientManager>,
}

struct InternalClientManager {
    backend: Box<dyn ClientManagerBackend>,
}

impl ClientManager {
    pub fn new(backend: Box<dyn ClientManagerBackend>) -> Self {
        Self {
            internal: Arc::new(InternalClientManager { backend }),
        }
    }

    pub async fn get_client(&self, user_id: &UserId) -> Option<bitwarden_core::Client> {
        self.internal.backend.get_client(user_id).await
    }

    pub async fn set_client(
        &self,
        client: bitwarden_core::Client,
    ) -> Result<(), ClientHasNoUserIdError> {
        self.internal.backend.set_client(client).await
    }

    pub async fn delete_client(&self, user_id: &UserId) {
        self.internal.backend.delete_client(user_id).await;
    }
}

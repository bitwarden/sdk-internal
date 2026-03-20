use std::collections::HashMap;

use bitwarden_core::UserId;
use tokio::sync::Mutex;

use crate::backend::{ClientHasNoUserIdError, ClientManagerBackend};

pub struct SdkManagedBackend {
    clients: Mutex<HashMap<UserId, bitwarden_core::Client>>,
}

impl Default for SdkManagedBackend {
    fn default() -> Self {
        Self {
            clients: Mutex::new(HashMap::new()),
        }
    }
}

impl SdkManagedBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl ClientManagerBackend for SdkManagedBackend {
    async fn get_client(&self, user_id: &UserId) -> Option<bitwarden_core::Client> {
        let clients = self.clients.lock().await;
        clients.get(user_id).cloned()
    }

    async fn set_client(&self, client: bitwarden_core::Client) -> Result<(), ClientHasNoUserIdError> {
        let user_id = client
            .internal
            .get_user_id()
            .ok_or(ClientHasNoUserIdError)?;
        let mut clients = self.clients.lock().await;
        clients.insert(user_id, client);
        Ok(())
    }

    async fn delete_client(&self, user_id: &UserId) {
        let mut clients = self.clients.lock().await;
        clients.remove(user_id);
    }
}

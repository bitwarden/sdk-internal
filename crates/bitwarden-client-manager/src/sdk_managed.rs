use std::collections::HashMap;

use tokio::sync::Mutex;

pub struct SdkManagedBackend {
    clients: Mutex<HashMap<String, bitwarden_core::Client>>,
}

impl SdkManagedBackend {
    pub fn new() -> Self {
        Self {
            clients: Mutex::new(HashMap::new()),
        }
    }

    pub async fn get_client(&self, client_id: &str) -> Option<bitwarden_core::Client> {
        let clients = self.clients.lock().await;
        clients.get(client_id).cloned()
    }

    pub async fn set_client(&self, client_id: String, client: bitwarden_core::Client) {
        let mut clients = self.clients.lock().await;
        clients.insert(client_id, client);
    }

    pub async fn delete_client(&self, client_id: &str) {
        let mut clients = self.clients.lock().await;
        clients.remove(client_id);
    }
}

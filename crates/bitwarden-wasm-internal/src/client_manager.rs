use std::fmt::Display;

use bitwarden_core::UserId;
use bitwarden_error::bitwarden_error;
use bitwarden_pm::client_manager::ClientManager as InnerClientManager;
use wasm_bindgen::prelude::*;

use crate::PasswordManagerClient;

/// Manages multiple clients for the Bitwarden SDK in WebAssembly environments
#[wasm_bindgen]
pub struct ClientManager(InnerClientManager);

#[wasm_bindgen]
impl ClientManager {
    /// Create a new ClientManager using SDK-managed storage
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self(InnerClientManager::new(Box::new(
            bitwarden_client_manager::SdkManagedBackend::new(),
        )))
    }

    /// Get a client by its user ID
    pub async fn get_client(&self, user_id: UserId) -> Option<PasswordManagerClient> {
        self.0
            .get_client(&user_id)
            .await
            .map(|c| PasswordManagerClient(c))
    }

    /// Store a client, keyed by the user ID already set on the client.
    pub async fn set_client(&self, client: &PasswordManagerClient) -> Result<(), SetClientError> {
        self.0
            .0
            .set_client(client.0 .0.clone())
            .await
            .map_err(|e| SetClientError(e.to_string()))
    }

    /// Remove a client by its user ID
    pub async fn delete_client(&self, user_id: UserId) {
        self.0.delete_client(&user_id).await;
    }
}

#[bitwarden_error(basic)]
pub struct SetClientError(String);

impl Display for SetClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

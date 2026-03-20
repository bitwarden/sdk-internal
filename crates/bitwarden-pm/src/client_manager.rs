#![allow(missing_docs)]

use bitwarden_core::UserId;

use crate::PasswordManagerClient;

/// Manages multiple clients for the Bitwarden SDK, allowing for multiple accounts to be used in the
/// same application.
pub struct ClientManager(pub bitwarden_client_manager::ClientManager);

impl ClientManager {
    /// Create a new ClientManager with the provided backend implementation
    pub fn new(backend: Box<dyn bitwarden_client_manager::ClientManagerBackend>) -> Self {
        Self(bitwarden_client_manager::ClientManager::new(backend))
    }

    /// Get a client by its user ID, returning it wrapped as a PasswordManagerClient
    pub async fn get_client(&self, user_id: &UserId) -> Option<PasswordManagerClient> {
        self.0.get_client(user_id).await.map(PasswordManagerClient)
    }

    /// Store a client, keyed by the user ID already set on the client.
    ///
    /// Returns an error if the client does not have a user ID set.
    pub async fn set_client(
        &self,
        client: PasswordManagerClient,
    ) -> Result<(), bitwarden_client_manager::ClientHasNoUserIdError> {
        self.0.set_client(client.0).await
    }

    /// Remove a client by its user ID
    pub async fn delete_client(&self, user_id: &UserId) {
        self.0.delete_client(user_id).await;
    }
}

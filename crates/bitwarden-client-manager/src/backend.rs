use bitwarden_core::{Client, UserId};

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait ClientManagerBackend: Send + Sync {
    async fn get_client(&self, user_id: &UserId) -> Option<Client>;
    async fn set_client(&self, client: Client) -> Result<(), ClientHasNoUserIdError>;
    async fn delete_client(&self, user_id: &UserId);
}

#[derive(Debug, thiserror::Error)]
#[error("client does not have a user ID set")]
pub struct ClientHasNoUserIdError;

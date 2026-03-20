use bitwarden_core::Client;

#[async_trait::async_trait]
pub trait ClientManagerBackend {
    async fn get_client(&self, client_id: &str) -> Option<Client>;
    async fn set_client(&self, client: Client);
    async fn delete_client(&self, client_id: &str);
}

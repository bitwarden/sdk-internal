use bitwarden_core::Client;

use crate::{
    sync::{sync, SyncError},
    SyncRequest, SyncResponse,
};

#[derive(Clone)]
pub struct VaultClient {
    pub(crate) client: Client,
}

impl VaultClient {
    fn new(client: Client) -> Self {
        Self { client }
    }

    pub async fn sync(&self, input: &SyncRequest) -> Result<SyncResponse, SyncError> {
        sync(&self.client, input).await
    }
}

pub trait VaultClientExt {
    fn vault(&self) -> VaultClient;
}

impl VaultClientExt for Client {
    fn vault(&self) -> VaultClient {
        VaultClient::new(self.clone())
    }
}

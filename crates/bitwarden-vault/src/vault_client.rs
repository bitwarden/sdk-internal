use bitwarden_core::Client;

use crate::{
    sync::{sync, SyncError},
    SyncRequest, SyncResponse,
};

pub struct VaultClient<'a> {
    pub(crate) client: &'a Client,
}

impl<'a> VaultClient<'a> {
    fn new(client: &'a Client) -> Self {
        Self { client }
    }

    pub async fn sync(&self, input: &SyncRequest) -> Result<SyncResponse, SyncError> {
        sync(self.client, input).await
    }
}

pub trait VaultClientExt<'a> {
    fn vault(&'a self) -> VaultClient<'a>;
}

impl<'a> VaultClientExt<'a> for Client {
    fn vault(&'a self) -> VaultClient<'a> {
        VaultClient::new(self)
    }
}

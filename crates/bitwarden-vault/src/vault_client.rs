use bitwarden_core::Client;

use crate::{
    sync::{sync, SyncError},
    Cipher, SyncRequest, SyncResponse,
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

    pub async fn print_the_ciphers(&self) -> String {
        let store = self
            .client
            .internal
            .get_repository::<Cipher>()
            .expect("msg");
        let mut result = String::new();
        let ciphers = store.list().await.expect("msg");
        for cipher in ciphers {
            result.push_str(&serde_json::to_string(&cipher).expect("msg"));
            result.push('\n');
        }
        result
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

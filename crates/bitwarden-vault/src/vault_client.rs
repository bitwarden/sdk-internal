use bitwarden_core::Client;

use crate::{
    sync::{sync, SyncError},
    AttachmentsClient, CiphersClient, CollectionsClient, FoldersClient, PasswordHistoryClient,
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

    pub fn attachments(&self) -> AttachmentsClient {
        AttachmentsClient {
            client: self.client.clone(),
        }
    }

    pub fn ciphers(&self) -> CiphersClient {
        CiphersClient {
            client: self.client.clone(),
        }
    }

    pub fn collections(&self) -> CollectionsClient {
        CollectionsClient {
            client: self.client.clone(),
        }
    }

    pub fn folders(&self) -> FoldersClient {
        FoldersClient {
            client: self.client.clone(),
        }
    }

    pub fn password_history(&self) -> PasswordHistoryClient {
        PasswordHistoryClient {
            client: self.client.clone(),
        }
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

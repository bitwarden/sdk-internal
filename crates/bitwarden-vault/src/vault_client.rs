use bitwarden_core::Client;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    AttachmentsClient, CiphersClient, FoldersClient, PasswordHistoryClient, SyncRequest,
    SyncResponse, TotpClient,
    collection_client::CollectionsClient,
    sync::{SyncError, sync},
};

#[allow(missing_docs)]
#[derive(Clone)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct VaultClient {
    pub(crate) client: Client,
}

impl VaultClient {
    fn new(client: Client) -> Self {
        Self { client }
    }

    #[allow(missing_docs)]
    pub async fn sync(&self, input: &SyncRequest) -> Result<SyncResponse, SyncError> {
        sync(&self.client, input).await
    }

    /// Password history related operations.
    pub fn password_history(&self) -> PasswordHistoryClient {
        PasswordHistoryClient {
            client: self.client.clone(),
        }
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl VaultClient {
    /// Attachment related operations.
    pub fn attachments(&self) -> AttachmentsClient {
        AttachmentsClient {
            client: self.client.clone(),
        }
    }

    /// Cipher related operations.
    pub fn ciphers(&self) -> CiphersClient {
        CiphersClient {
            client: self.client.clone(),
        }
    }

    /// Folder related operations.
    pub fn folders(&self) -> FoldersClient {
        FoldersClient {
            client: self.client.clone(),
        }
    }

    /// TOTP related operations.
    pub fn totp(&self) -> TotpClient {
        TotpClient {
            client: self.client.clone(),
        }
    }

    /// Collection related operations.
    pub fn collections(&self) -> CollectionsClient {
        CollectionsClient {
            client: self.client.clone(),
        }
    }
}

#[allow(missing_docs)]
pub trait VaultClientExt {
    fn vault(&self) -> VaultClient;
}

impl VaultClientExt for Client {
    fn vault(&self) -> VaultClient {
        VaultClient::new(self.clone())
    }
}

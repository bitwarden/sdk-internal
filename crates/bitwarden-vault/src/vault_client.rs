use bitwarden_core::Client;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    sync::{sync, SyncError},
    AttachmentsClient, Cipher, CiphersClient, CollectionsClient, FoldersClient,
    PasswordHistoryClient, SyncRequest, SyncResponse, TotpClient,
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

    /// Collection related operations.
    pub fn collections(&self) -> CollectionsClient {
        CollectionsClient {
            client: self.client.clone(),
        }
    }

    /// Password history related operations.
    pub fn password_history(&self) -> PasswordHistoryClient {
        PasswordHistoryClient {
            client: self.client.clone(),
        }
    }

    /// Test method, prints all ciphers in the vault
    pub async fn print_the_ciphers(&self) -> String {
        let store = self
            .client
            .platform()
            .state()
            .get_repository::<Cipher>()
            .expect("msg");
        let mut result = String::new();
        let ciphers = store.list().await.expect("msg");
        for cipher in ciphers {
            result.push_str(format!("{cipher:?}\n").as_str());
        }
        result
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

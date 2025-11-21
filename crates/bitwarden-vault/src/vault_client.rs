use bitwarden_core::Client;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    AttachmentsClient, CipherRiskClient, CiphersClient, FoldersClient, PasswordHistoryClient,
    TotpClient, collection_client::CollectionsClient,
};

#[expect(missing_docs)]
#[derive(Clone)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct VaultClient {
    pub(crate) client: Client,
}

impl VaultClient {
    fn new(client: Client) -> Self {
        Self { client }
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

    /// Cipher risk evaluation operations.
    pub fn cipher_risk(&self) -> CipherRiskClient {
        CipherRiskClient {
            client: self.client.clone(),
        }
    }
}

#[expect(missing_docs)]
pub trait VaultClientExt {
    fn vault(&self) -> VaultClient;
}

impl VaultClientExt for Client {
    fn vault(&self) -> VaultClient {
        VaultClient::new(self.clone())
    }
}

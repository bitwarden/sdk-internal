use bitwarden_collections::collection_client::CollectionsClient;
use bitwarden_core::{Client, FromClient};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    AttachmentsClient, CipherRiskClient, CiphersClient, FoldersClient, PasswordHistoryClient,
    TotpClient,
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

    /// Password history related operations.
    pub fn password_history(&self) -> PasswordHistoryClient {
        PasswordHistoryClient {
            client: self.client.clone(),
        }
    }
}

// Registers the vault client's introspectable children for the object-graph
// discovery API. Each listed accessor is called on demand during a crawl and
// its result introspected, so the accessor's return type must implement
// `Introspect`. Add more accessors here as their clients gain that impl.
#[bitwarden_introspect_macro::introspect_methods(folders, ciphers)]
impl VaultClient {}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl VaultClient {
    /// Attachment related operations.
    pub fn attachments(&self) -> AttachmentsClient {
        AttachmentsClient::from_client(&self.client)
    }

    /// Cipher related operations.
    pub fn ciphers(&self) -> CiphersClient {
        CiphersClient::from_client(&self.client)
    }

    /// Folder related operations.
    pub fn folders(&self) -> FoldersClient {
        FoldersClient::from_client(&self.client)
    }

    /// TOTP related operations.
    pub fn totp(&self) -> TotpClient {
        TotpClient {
            client: self.client.clone(),
        }
    }

    /// Collection related operations.
    ///
    /// This nested accessor is kept for backwards compatibility. New callers should prefer the
    /// `collections()` accessor registered directly on the top-level Password Manager client.
    pub fn collections(&self) -> CollectionsClient {
        CollectionsClient::from_client(&self.client)
    }

    /// Cipher risk evaluation operations.
    pub fn cipher_risk(&self) -> CipherRiskClient {
        CipherRiskClient {
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

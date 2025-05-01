pub mod attachments;
pub mod ciphers;
pub mod folders;
pub mod totp;

use attachments::AttachmentsClient;
use ciphers::CiphersClient;
use totp::TotpClient;
use wasm_bindgen::prelude::*;

use crate::FoldersClient;

#[wasm_bindgen]
pub struct VaultClient(bitwarden_vault::VaultClient);

impl VaultClient {
    pub fn new(client: bitwarden_vault::VaultClient) -> Self {
        Self(client)
    }
}

#[wasm_bindgen]
impl VaultClient {
    pub fn attachments(&self) -> AttachmentsClient {
        AttachmentsClient::new(self.0.attachments())
    }

    pub fn ciphers(&self) -> CiphersClient {
        CiphersClient::new(self.0.ciphers())
    }

    pub fn folders(&self) -> FoldersClient {
        FoldersClient::new(self.0.folders())
    }

    pub fn totp(&self) -> TotpClient {
        TotpClient::new(self.0.clone())
    }
}

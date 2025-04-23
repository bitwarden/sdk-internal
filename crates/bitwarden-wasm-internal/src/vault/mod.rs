pub mod attachments;
pub mod ciphers;
pub mod folders;
pub mod totp;

use attachments::ClientAttachments;
use ciphers::ClientCiphers;
use totp::ClientTotp;
use wasm_bindgen::prelude::*;

use crate::ClientFolders;

#[wasm_bindgen]
pub struct VaultClient(bitwarden_vault::VaultClient);

impl VaultClient {
    pub fn new(client: bitwarden_vault::VaultClient) -> Self {
        Self(client)
    }
}

#[wasm_bindgen]
impl VaultClient {
    pub fn attachments(&self) -> ClientAttachments {
        ClientAttachments::new(self.0.attachments())
    }

    pub fn ciphers(&self) -> ClientCiphers {
        ClientCiphers::new(self.0.ciphers())
    }

    pub fn folders(&self) -> ClientFolders {
        ClientFolders::new(self.0.folders())
    }

    pub fn totp(&self) -> ClientTotp {
        ClientTotp::new(self.0.clone())
    }
}

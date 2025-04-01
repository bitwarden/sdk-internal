pub mod folders;
pub mod totp;

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
    pub fn folders(&self) -> ClientFolders {
        ClientFolders::new(self.0.folders())
    }

    pub fn totp(&self) -> ClientTotp {
        ClientTotp::new(self.0.clone())
    }
}

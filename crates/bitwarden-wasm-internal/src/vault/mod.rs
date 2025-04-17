pub mod ciphers;
pub mod folders;
pub mod totp;

use std::rc::Rc;

use bitwarden_core::Client;
use ciphers::ClientCiphers;
use totp::ClientTotp;
use wasm_bindgen::prelude::*;

use crate::ClientFolders;

#[wasm_bindgen]
pub struct VaultClient(Rc<Client>);

impl VaultClient {
    pub fn new(client: Rc<Client>) -> Self {
        Self(client)
    }
}

#[wasm_bindgen]
impl VaultClient {
    pub fn ciphers(&self) -> ClientCiphers {
        ClientCiphers::new(self.0.clone())
    }

    pub fn folders(&self) -> ClientFolders {
        ClientFolders::new(self.0.clone())
    }

    pub fn totp(&self) -> ClientTotp {
        ClientTotp::new(self.0.clone())
    }
}

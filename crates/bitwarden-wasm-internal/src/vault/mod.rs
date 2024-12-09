pub mod folders;

use std::rc::Rc;

use bitwarden_core::Client;
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
    pub fn folders(&self) -> ClientFolders {
        ClientFolders::new(self.0.clone())
    }
}

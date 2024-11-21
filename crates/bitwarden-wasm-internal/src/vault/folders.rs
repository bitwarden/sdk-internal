use std::rc::Rc;

use bitwarden_core::Client;
use bitwarden_vault::{ClientVaultExt, Folder, FolderView};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct ClientFolders(Rc<Client>);

impl ClientFolders {
    pub fn new(client: Rc<Client>) -> Self {
        Self(client)
    }
}

#[wasm_bindgen]
impl ClientFolders {
    /// Decrypt folder
    pub fn decrypt(&self, folder: Folder) -> Result<FolderView, bitwarden_core::Error> {
        self.0.vault().folders().decrypt(folder)
    }
}

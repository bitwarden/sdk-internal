use bitwarden_vault::{DecryptError, Folder, FolderView};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct ClientFolders(bitwarden_vault::ClientFolders);

impl ClientFolders {
    pub fn new(client: bitwarden_vault::ClientFolders) -> Self {
        Self(client)
    }
}

#[wasm_bindgen]
impl ClientFolders {
    /// Decrypt folder
    pub fn decrypt(&self, folder: Folder) -> Result<FolderView, DecryptError> {
        self.0.decrypt(folder)
    }
}

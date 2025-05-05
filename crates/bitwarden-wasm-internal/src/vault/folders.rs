use bitwarden_vault::{DecryptError, Folder, FolderView};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct FoldersClient(bitwarden_vault::FoldersClient);

impl FoldersClient {
    pub fn new(client: bitwarden_vault::FoldersClient) -> Self {
        Self(client)
    }
}

#[wasm_bindgen]
impl FoldersClient {
    /// Decrypt folder
    pub fn decrypt(&self, folder: Folder) -> Result<FolderView, DecryptError> {
        self.0.decrypt(folder)
    }
}

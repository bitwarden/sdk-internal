use bitwarden_core::Client;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    error::{DecryptError, EncryptError},
    Folder, FolderView,
};

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct FoldersClient {
    pub(crate) client: Client,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl FoldersClient {
    pub fn encrypt(&self, folder_view: FolderView) -> Result<Folder, EncryptError> {
        let key_store = self.client.internal.get_key_store();
        let folder = key_store.encrypt(folder_view)?;
        Ok(folder)
    }

    pub fn decrypt(&self, folder: Folder) -> Result<FolderView, DecryptError> {
        let key_store = self.client.internal.get_key_store();
        let folder_view = key_store.decrypt(&folder)?;
        Ok(folder_view)
    }

    pub fn decrypt_list(&self, folders: Vec<Folder>) -> Result<Vec<FolderView>, DecryptError> {
        let key_store = self.client.internal.get_key_store();
        let views = key_store.decrypt_list(&folders)?;
        Ok(views)
    }
}

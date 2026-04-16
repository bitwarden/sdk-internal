use std::sync::Arc;

use bitwarden_core::{FromClient, client::ApiConfigurations, key_management::KeySlotIds};
use bitwarden_crypto::KeyStore;
use bitwarden_state::repository::Repository;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    Folder, FolderView,
    error::{DecryptError, EncryptError},
};

/// Wrapper for folder specific functionality.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(FromClient)]
pub struct FoldersClient {
    pub(crate) key_store: KeyStore<KeySlotIds>,
    pub(crate) api_configurations: Arc<ApiConfigurations>,
    pub(crate) repository: Option<Arc<dyn Repository<Folder>>>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[deprecated(
    note = "Use the higher level `FoldersClient` methods instead, which handle encryption and decryption for you."
)]
impl FoldersClient {
    /// Encrypt a [FolderView] to a [Folder].
    pub fn encrypt(&self, folder_view: FolderView) -> Result<Folder, EncryptError> {
        let folder = self.key_store.encrypt(folder_view)?;
        Ok(folder)
    }

    /// Decrypt a [Folder] to [FolderView].
    pub fn decrypt(&self, folder: Folder) -> Result<FolderView, DecryptError> {
        let folder_view = self.key_store.decrypt(&folder)?;
        Ok(folder_view)
    }

    /// Decrypt a list of [Folder]s to a list of [FolderView]s.
    pub fn decrypt_list(&self, folders: Vec<Folder>) -> Result<Vec<FolderView>, DecryptError> {
        let views = self.key_store.decrypt_list(&folders)?;
        Ok(views)
    }
}

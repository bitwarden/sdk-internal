use std::sync::Arc;

use bitwarden_core::Client;

use bitwarden_state::repository::{Repository, RepositoryError};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    error::{DecryptError, EncryptError},
    folder::{create_folder, edit_folder},
    CreateFolderError, EditFolderError, Folder, FolderAddEditRequest, FolderView,
};

#[allow(missing_docs)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct FoldersClient {
    pub(crate) client: Client,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl FoldersClient {
    #[allow(missing_docs)]
    pub fn encrypt(&self, folder_view: FolderView) -> Result<Folder, EncryptError> {
        let key_store = self.client.internal.get_key_store();
        let folder = key_store.encrypt(folder_view)?;
        Ok(folder)
    }

    #[allow(missing_docs)]
    pub fn decrypt(&self, folder: Folder) -> Result<FolderView, DecryptError> {
        let key_store = self.client.internal.get_key_store();
        let folder_view = key_store.decrypt(&folder)?;
        Ok(folder_view)
    }

    #[allow(missing_docs)]
    pub fn decrypt_list(&self, folders: Vec<Folder>) -> Result<Vec<FolderView>, DecryptError> {
        let key_store = self.client.internal.get_key_store();
        let views = key_store.decrypt_list(&folders)?;
        Ok(views)
    }

    /// Create a new folder and save it to the server.
    pub async fn create(
        &self,
        request: FolderAddEditRequest,
    ) -> Result<FolderView, CreateFolderError> {
        let key_store = self.client.internal.get_key_store();
        let config = self.client.internal.get_api_configurations().await;
        let repository = self.get_repository()?;

        create_folder(key_store, &config.api, &repository, request).await
    }

    /// Edit the folder.
    pub async fn edit(
        &self,
        folder_id: &str,
        request: FolderAddEditRequest,
    ) -> Result<FolderView, EditFolderError> {
        let key_store = self.client.internal.get_key_store();
        let config = self.client.internal.get_api_configurations().await;
        let repository = self.get_repository()?;

        edit_folder(key_store, &config.api, &repository, folder_id, request).await
    }
}

impl FoldersClient {
    fn get_repository(&self) -> Result<Arc<dyn Repository<Folder>>, RepositoryError> {
        Ok(self
            .client
            .platform()
            .state()
            .get_client_managed::<Folder>()?)
    }
}

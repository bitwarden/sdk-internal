use std::sync::Arc;

use bitwarden_core::Client;
use bitwarden_state::repository::{Repository, RepositoryError};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    CreateFolderError, EditFolderError, Folder, FolderAddEditRequest, FolderId, FolderView,
    GetFolderError,
    error::{DecryptError, EncryptError},
    folder::{create_folder, edit_folder, get_folder, list_folders},
};

/// Wrapper for folder specific functionality.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct FoldersClient {
    pub(crate) client: Client,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl FoldersClient {
    /// Encrypt a [FolderView] to a [Folder].
    pub fn encrypt(&self, folder_view: FolderView) -> Result<Folder, EncryptError> {
        let key_store = self.client.internal.get_key_store();
        let folder = key_store.encrypt(folder_view)?;
        Ok(folder)
    }

    /// Encrypt a [Folder] to [FolderView].
    pub fn decrypt(&self, folder: Folder) -> Result<FolderView, DecryptError> {
        let key_store = self.client.internal.get_key_store();
        let folder_view = key_store.decrypt(&folder)?;
        Ok(folder_view)
    }

    /// Decrypt a list of [Folder]s to a list of [FolderView]s.
    pub fn decrypt_list(&self, folders: Vec<Folder>) -> Result<Vec<FolderView>, DecryptError> {
        let key_store = self.client.internal.get_key_store();
        let views = key_store.decrypt_list(&folders)?;
        Ok(views)
    }

    /// Get all folders from state and decrypt them to a list of [FolderView].
    pub async fn list(&self) -> Result<Vec<FolderView>, GetFolderError> {
        let key_store = self.client.internal.get_key_store();
        let repository = self.get_repository()?;

        list_folders(key_store, repository.as_ref()).await
    }

    /// Get a specific [Folder] by its ID from state and decrypt it to a [FolderView].
    pub async fn get(&self, folder_id: FolderId) -> Result<FolderView, GetFolderError> {
        let key_store = self.client.internal.get_key_store();
        let repository = self.get_repository()?;

        get_folder(key_store, repository.as_ref(), folder_id).await
    }

    /// Create a new [Folder] and save it to the server.
    pub async fn create(
        &self,
        request: FolderAddEditRequest,
    ) -> Result<FolderView, CreateFolderError> {
        let key_store = self.client.internal.get_key_store();
        let config = self.client.internal.get_api_configurations().await;
        let repository = self.get_repository()?;

        create_folder(key_store, &config.api_client, repository.as_ref(), request).await
    }

    /// Edit the [Folder] and save it to the server.
    pub async fn edit(
        &self,
        folder_id: FolderId,
        request: FolderAddEditRequest,
    ) -> Result<FolderView, EditFolderError> {
        let key_store = self.client.internal.get_key_store();
        let config = self.client.internal.get_api_configurations().await;
        let repository = self.get_repository()?;

        edit_folder(
            key_store,
            &config.api_client,
            repository.as_ref(),
            folder_id,
            request,
        )
        .await
    }
}

impl FoldersClient {
    /// Helper for getting the repository for folders.
    fn get_repository(&self) -> Result<Arc<dyn Repository<Folder>>, RepositoryError> {
        Ok(self
            .client
            .platform()
            .state()
            .get_client_managed::<Folder>()?)
    }
}

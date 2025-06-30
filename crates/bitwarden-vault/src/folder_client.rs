use bitwarden_api_api::{apis::folders_api, models::FolderRequestModel};
use bitwarden_core::{ApiError, Client};
use bitwarden_error::bitwarden_error;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify_next::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    error::{DecryptError, EncryptError},
    Folder, FolderView, VaultParseError,
};

/// Request to add or edit a folder.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct FolderAddEditRequest {
    pub name: String,
}

#[allow(missing_docs)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct FoldersClient {
    pub(crate) client: Client,
}

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum CreateFolderError {
    #[error(transparent)]
    Encrypt(#[from] EncryptError),
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    VaultParse(#[from] VaultParseError),
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
    pub async fn create(&self, request: FolderAddEditRequest) -> Result<Folder, CreateFolderError> {
        // TODO: We should probably not use a Folder model here, but rather create FolderRequestModel directly?
        let folder = self.encrypt(FolderView {
            id: None,
            name: request.name,
            revision_date: Utc::now(),
        })?;

        let config = self.client.internal.get_api_configurations().await;
        let req = folders_api::folders_post(
            &config.api,
            Some(FolderRequestModel {
                name: folder.name.to_string(),
            }),
        )
        .await
        .map_err(ApiError::from)?;

        Ok(req.try_into()?)
    }

    /// Edit the folder.
    ///
    /// TODO: Replace `old_folder` with `FolderId` and load the old folder from state.
    /// TODO: Save the folder to the server and state.
    pub fn edit_without_state(
        &self,
        old_folder: Folder,
        folder: FolderAddEditRequest,
    ) -> Result<Folder, EncryptError> {
        self.encrypt(FolderView {
            id: old_folder.id,
            name: folder.name,
            revision_date: old_folder.revision_date,
        })
    }
}

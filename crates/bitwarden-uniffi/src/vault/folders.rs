use bitwarden_vault::{Folder, FolderAddEditRequest, FolderId, FolderView};

use crate::Result;

#[allow(missing_docs)]
#[derive(uniffi::Object)]
pub struct FoldersClient(pub(crate) bitwarden_vault::FoldersClient);

#[uniffi::export(async_runtime = "tokio")]
impl FoldersClient {
    /// Encrypt folder
    pub fn encrypt(&self, folder: FolderView) -> Result<Folder> {
        #[allow(deprecated)]
        Ok(self.0.encrypt(folder)?)
    }

    /// Decrypt folder
    pub fn decrypt(&self, folder: Folder) -> Result<FolderView> {
        #[allow(deprecated)]
        Ok(self.0.decrypt(folder)?)
    }

    /// Decrypt folder list
    pub fn decrypt_list(&self, folders: Vec<Folder>) -> Result<Vec<FolderView>> {
        #[allow(deprecated)]
        Ok(self.0.decrypt_list(folders)?)
    }

    /// Create a new folder and save it to the server and local state
    pub async fn create(&self, request: FolderAddEditRequest) -> Result<FolderView> {
        Ok(self.0.create(request).await?)
    }

    /// Edit an existing folder and save it to the server and local state
    pub async fn edit(
        &self,
        folder_id: FolderId,
        request: FolderAddEditRequest,
    ) -> Result<FolderView> {
        Ok(self.0.edit(folder_id, request).await?)
    }

    /// Get a folder from local state and decrypt it
    pub async fn get(&self, folder_id: FolderId) -> Result<FolderView> {
        Ok(self.0.get(folder_id).await?)
    }

    /// Get all folders from local state and decrypt them
    pub async fn list(&self) -> Result<Vec<FolderView>> {
        Ok(self.0.list().await?)
    }
}

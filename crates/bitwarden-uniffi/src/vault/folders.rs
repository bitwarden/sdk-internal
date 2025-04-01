use bitwarden_vault::{Folder, FolderView};

use crate::{error::Error, Result};

#[derive(uniffi::Object)]
pub struct ClientFolders(pub(crate) bitwarden_vault::ClientFolders);

#[uniffi::export]
impl ClientFolders {
    /// Encrypt folder
    pub fn encrypt(&self, folder: FolderView) -> Result<Folder> {
        Ok(self.0.encrypt(folder).map_err(Error::Encrypt)?)
    }

    /// Decrypt folder
    pub fn decrypt(&self, folder: Folder) -> Result<FolderView> {
        Ok(self.0.decrypt(folder).map_err(Error::Decrypt)?)
    }

    /// Decrypt folder list
    pub fn decrypt_list(&self, folders: Vec<Folder>) -> Result<Vec<FolderView>> {
        Ok(self.0.decrypt_list(folders).map_err(Error::Decrypt)?)
    }
}

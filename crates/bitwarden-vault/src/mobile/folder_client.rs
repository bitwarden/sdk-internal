use bitwarden_core::Client;
use bitwarden_crypto::{KeyDecryptable, KeyEncryptable};

use crate::{
    error::{DecryptError, EncryptError},
    Folder, FolderView, VaultClient,
};

pub struct ClientFolders<'a> {
    pub(crate) client: &'a Client,
}

impl ClientFolders<'_> {
    pub fn encrypt(&self, folder_view: FolderView) -> Result<Folder, EncryptError> {
        let enc = self.client.internal.get_encryption_settings()?;
        let key = enc.get_key(&None)?;

        let folder = folder_view.encrypt_with_key(key)?;

        Ok(folder)
    }

    pub fn decrypt(&self, folder: Folder) -> Result<FolderView, DecryptError> {
        let enc = self.client.internal.get_encryption_settings()?;
        let key = enc.get_key(&None)?;

        let folder_view = folder.decrypt_with_key(key)?;

        Ok(folder_view)
    }

    pub fn decrypt_list(&self, folders: Vec<Folder>) -> Result<Vec<FolderView>, DecryptError> {
        let enc = self.client.internal.get_encryption_settings()?;
        let key = enc.get_key(&None)?;

        let views = folders.decrypt_with_key(key)?;

        Ok(views)
    }
}

impl<'a> VaultClient<'a> {
    pub fn folders(&'a self) -> ClientFolders<'a> {
        ClientFolders {
            client: self.client,
        }
    }
}

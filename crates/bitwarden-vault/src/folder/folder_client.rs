use std::sync::Arc;

use bitwarden_core::{client::ApiProvider, key_management::KeyIds};
use bitwarden_crypto::KeyStore;
use bitwarden_state::repository::Repository;
use bitwarden_test_macro::from_client;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    CreateFolderError, EditFolderError, Folder, FolderAddEditRequest, FolderId, FolderView,
    GetFolderError,
    error::{DecryptError, EncryptError},
    folder::{create_folder, edit_folder, get_folder, list_folders},
};

/// Wrapper for folder specific functionality.
#[from_client]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct FoldersClient {
    key_store: KeyStore<KeyIds>,
    api_config_provider: Arc<dyn ApiProvider>,
    repository: Arc<dyn Repository<Folder>>,
}

impl FoldersClient {
    /// Creates a new FoldersClient with explicit dependencies.
    ///
    /// This constructor is useful for testing, allowing dependencies to be mocked.
    #[cfg(test)]
    pub(crate) fn new(
        key_store: KeyStore<KeyIds>,
        api_config_provider: Arc<dyn ApiProvider>,
        repository: Arc<dyn Repository<Folder>>,
    ) -> Self {
        Self {
            key_store,
            api_config_provider,
            repository,
        }
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl FoldersClient {
    /// Encrypt a [FolderView] to a [Folder].
    pub fn encrypt(&self, folder_view: FolderView) -> Result<Folder, EncryptError> {
        let folder = self.key_store.encrypt(folder_view)?;
        Ok(folder)
    }

    /// Encrypt a [Folder] to [FolderView].
    pub fn decrypt(&self, folder: Folder) -> Result<FolderView, DecryptError> {
        let folder_view = self.key_store.decrypt(&folder)?;
        Ok(folder_view)
    }

    /// Decrypt a list of [Folder]s to a list of [FolderView]s.
    pub fn decrypt_list(&self, folders: Vec<Folder>) -> Result<Vec<FolderView>, DecryptError> {
        let views = self.key_store.decrypt_list(&folders)?;
        Ok(views)
    }

    /// Get all folders from state and decrypt them to a list of [FolderView].
    pub async fn list(&self) -> Result<Vec<FolderView>, GetFolderError> {
        list_folders(&self.key_store, self.repository.as_ref()).await
    }

    /// Get a specific [Folder] by its ID from state and decrypt it to a [FolderView].
    pub async fn get(&self, folder_id: FolderId) -> Result<FolderView, GetFolderError> {
        get_folder(&self.key_store, self.repository.as_ref(), folder_id).await
    }

    /// Create a new [Folder] and save it to the server.
    pub async fn create(
        &self,
        request: FolderAddEditRequest,
    ) -> Result<FolderView, CreateFolderError> {
        let config = self.api_config_provider.get_api_configurations().await;
        create_folder(
            &self.key_store,
            &config.api_client,
            self.repository.as_ref(),
            request,
        )
        .await
    }

    /// Edit the [Folder] and save it to the server.
    pub async fn edit(
        &self,
        folder_id: FolderId,
        request: FolderAddEditRequest,
    ) -> Result<FolderView, EditFolderError> {
        let config = self.api_config_provider.get_api_configurations().await;
        edit_folder(
            &self.key_store,
            &config.api_client,
            self.repository.as_ref(),
            folder_id,
            request,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::{client::internal::MockApiProvider, key_management::SymmetricKeyId};
    use bitwarden_crypto::{PrimitiveEncryptable, SymmetricKeyAlgorithm};
    use bitwarden_test::MemoryRepository;
    use uuid::uuid;

    use super::*;

    async fn repository_add_folder(
        repository: &MemoryRepository<Folder>,
        store: &KeyStore<KeyIds>,
        folder_id: FolderId,
        name: &str,
    ) {
        let folder = Folder {
            id: Some(folder_id),
            name: name
                .encrypt(&mut store.context(), SymmetricKeyId::User)
                .unwrap(),
            revision_date: "2024-01-01T00:00:00Z".parse().unwrap(),
        };
        repository.set(folder_id.to_string(), folder).await.unwrap();
    }

    #[tokio::test]
    async fn test_list() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        {
            let mut ctx = store.context_mut();
            let local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(local_key_id, SymmetricKeyId::User)
                .unwrap();
        }

        let repository = Arc::new(MemoryRepository::<Folder>::default());

        let folder_id_1 = FolderId::new(uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1"));
        let folder_id_2 = FolderId::new(uuid!("35afb11c-9c95-4db5-8bac-c21cb204a3f2"));

        repository_add_folder(&repository, &store, folder_id_1, "folder1").await;
        repository_add_folder(&repository, &store, folder_id_2, "folder2").await;

        let client = FoldersClient::new(store, Arc::new(MockApiProvider::new()), repository);

        let result = client.list().await.unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.iter().any(|f| f.name == "folder1"));
        assert!(result.iter().any(|f| f.name == "folder2"));
    }

    #[tokio::test]
    async fn test_list_empty() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        {
            let mut ctx = store.context_mut();
            let local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            ctx.persist_symmetric_key(local_key_id, SymmetricKeyId::User)
                .unwrap();
        }

        let repository = Arc::new(MemoryRepository::<Folder>::default());

        let client = FoldersClient::new(store, Arc::new(MockApiProvider::new()), repository);

        let result = client.list().await.unwrap();

        assert!(result.is_empty());
    }
}

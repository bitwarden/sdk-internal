use bitwarden_crypto::CryptoError;
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::RepositoryError;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{FolderId, FolderView, FoldersClient, ItemNotFoundError};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum GetFolderError {
    #[error(transparent)]
    ItemNotFound(#[from] ItemNotFoundError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl FoldersClient {
    /// Get a specific [crate::Folder] by its ID from state and decrypt it to a [FolderView].
    pub async fn get(&self, folder_id: FolderId) -> Result<FolderView, GetFolderError> {
        let folder = self
            .repository
            .get(folder_id)
            .await?
            .ok_or(ItemNotFoundError)?;

        Ok(self.key_store.decrypt(&folder)?)
    }

    /// Get all folders from state and decrypt them to a list of [FolderView].
    pub async fn list(&self) -> Result<Vec<FolderView>, GetFolderError> {
        let folders = self.repository.list().await?;
        let views = self.key_store.decrypt_list(&folders)?;
        Ok(views)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bitwarden_api_api::apis::ApiClient;
    use bitwarden_core::{
        client::ApiConfigurations, key_management::create_test_crypto_with_user_key,
    };
    use bitwarden_crypto::SymmetricCryptoKey;
    use bitwarden_test::MemoryRepository;
    use uuid::uuid;

    use super::*;
    use crate::Folder;

    fn create_client() -> FoldersClient {
        let store =
            create_test_crypto_with_user_key(SymmetricCryptoKey::make_aes256_cbc_hmac_key());
        let repository = Arc::new(MemoryRepository::<Folder>::default());

        FoldersClient {
            key_store: store,
            api_configurations: Arc::new(ApiConfigurations::from_api_client(
                ApiClient::new_mocked(|_| {}),
            )),
            repository,
        }
    }

    fn make_folder(client: &FoldersClient, id: FolderId, name: &str) -> Folder {
        client
            .key_store
            .encrypt(FolderView {
                id: Some(id),
                name: name.to_string(),
                revision_date: "2025-01-01T00:00:00Z".parse().unwrap(),
            })
            .unwrap()
    }

    #[tokio::test]
    async fn test_get_folder() {
        let client = create_client();
        let folder_id = FolderId::new(uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1"));
        let folder = make_folder(&client, folder_id, "Test Folder");

        client.repository.set(folder_id, folder).await.unwrap();

        let result = client.get(folder_id).await.unwrap();

        assert_eq!(
            result,
            FolderView {
                id: Some(folder_id),
                name: "Test Folder".to_string(),
                revision_date: "2025-01-01T00:00:00Z".parse().unwrap(),
            }
        );
    }

    #[tokio::test]
    async fn test_get_folder_not_found() {
        let client = create_client();
        let folder_id = FolderId::new(uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1"));

        let result = client.get(folder_id).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GetFolderError::ItemNotFound(_)
        ));
    }

    #[tokio::test]
    async fn test_list_folders() {
        let client = create_client();
        let id_a = FolderId::new(uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1"));
        let id_b = FolderId::new(uuid!("35afb11c-9c95-4db5-8bac-c21cb204a3f2"));

        client
            .repository
            .set(id_a, make_folder(&client, id_a, "Folder A"))
            .await
            .unwrap();
        client
            .repository
            .set(id_b, make_folder(&client, id_b, "Folder B"))
            .await
            .unwrap();

        let mut result = client.list().await.unwrap();
        result.sort_by(|a, b| a.name.cmp(&b.name));

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "Folder A");
        assert_eq!(result[1].name, "Folder B");
    }

    #[tokio::test]
    async fn test_list_folders_empty() {
        let client = create_client();

        let result = client.list().await.unwrap();

        assert!(result.is_empty());
    }
}

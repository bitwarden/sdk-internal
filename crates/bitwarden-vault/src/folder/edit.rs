use bitwarden_core::{ApiError, MissingFieldError};
use bitwarden_crypto::CryptoError;
use bitwarden_error::bitwarden_error;
use bitwarden_state::repository::{RepositoryError, RepositoryOption};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    Folder, FolderAddEditRequest, FolderId, FolderView, FoldersClient, ItemNotFoundError,
    VaultParseError,
};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EditFolderError {
    #[error(transparent)]
    ItemNotFound(#[from] ItemNotFoundError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    VaultParse(#[from] VaultParseError),
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    #[error(transparent)]
    Uuid(#[from] uuid::Error),
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl FoldersClient {
    /// Edit the [Folder] and save it to the server.
    pub async fn edit(
        &self,
        folder_id: FolderId,
        request: FolderAddEditRequest,
    ) -> Result<FolderView, EditFolderError> {
        let repository = self.repository.require()?;

        // Verify the folder we're updating exists
        repository.get(folder_id).await?.ok_or(ItemNotFoundError)?;

        let folder_request = self.key_store.encrypt(request)?;

        let resp = self
            .api_configurations
            .api_client
            .folders_api()
            .put(&folder_id.to_string(), Some(folder_request))
            .await
            .map_err(ApiError::from)?;

        let folder: Folder = resp.try_into()?;

        debug_assert!(folder.id.unwrap_or_default() == folder_id);

        repository.set(folder_id, folder.clone()).await?;

        Ok(self.key_store.decrypt(&folder)?)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bitwarden_api_api::{apis::ApiClient, models::FolderResponseModel};
    use bitwarden_core::{
        client::ApiConfigurations, key_management::create_test_crypto_with_user_key,
    };
    use bitwarden_crypto::SymmetricCryptoKey;
    use bitwarden_test::MemoryRepository;
    use uuid::uuid;

    use super::*;

    fn create_client(api_client: ApiClient) -> FoldersClient {
        FoldersClient {
            key_store: create_test_crypto_with_user_key(
                SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
            ),
            api_configurations: Arc::new(ApiConfigurations::from_api_client(api_client)),
            repository: Some(Arc::new(MemoryRepository::<Folder>::default())),
        }
    }

    async fn repository_add_folder(client: &FoldersClient, folder_id: FolderId, name: &str) {
        let folder_view = FolderView {
            id: Some(folder_id),
            name: name.to_string(),
            revision_date: "2024-01-01T00:00:00Z".parse().unwrap(),
        };
        let folder: Folder = client.key_store.encrypt(folder_view).unwrap();
        client
            .repository
            .as_ref()
            .unwrap()
            .set(folder_id, folder)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_edit_folder() {
        let folder_id = FolderId::new(uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1"));

        let client = create_client(ApiClient::new_mocked(move |mock| {
            mock.folders_api
                .expect_put()
                .returning(move |id, model| {
                    assert_eq!(id, folder_id.to_string());
                    Ok(FolderResponseModel {
                        object: Some("folder".to_string()),
                        id: Some(folder_id.into()),
                        name: Some(model.unwrap().name),
                        revision_date: Some("2025-01-01T00:00:00Z".to_string()),
                    })
                })
                .once();
        }));

        repository_add_folder(&client, folder_id, "old_name").await;

        let result = client
            .edit(
                folder_id,
                FolderAddEditRequest {
                    name: "test".to_string(),
                },
            )
            .await
            .unwrap();

        assert_eq!(
            result,
            FolderView {
                id: Some(folder_id),
                name: "test".to_string(),
                revision_date: "2025-01-01T00:00:00Z".parse().unwrap(),
            }
        );

        // Confirm the folder was updated in the repository
        assert_eq!(
            client
                .key_store
                .decrypt(
                    &client
                        .repository
                        .as_ref()
                        .unwrap()
                        .get(folder_id)
                        .await
                        .unwrap()
                        .unwrap()
                )
                .unwrap(),
            result
        );
    }

    #[tokio::test]
    async fn test_edit_folder_does_not_exist() {
        let folder_id = FolderId::new(uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1"));

        let client = create_client(ApiClient::new_mocked(|_| {}));

        let result = client
            .edit(
                folder_id,
                FolderAddEditRequest {
                    name: "test".to_string(),
                },
            )
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EditFolderError::ItemNotFound(_)
        ));
    }

    #[tokio::test]
    async fn test_edit_folder_http_error() {
        let folder_id = FolderId::new(uuid!("25afb11c-9c95-4db5-8bac-c21cb204a3f1"));

        let client = create_client(ApiClient::new_mocked(move |mock| {
            mock.folders_api.expect_put().returning(move |_id, _model| {
                Err(bitwarden_api_api::apis::Error::Io(std::io::Error::other(
                    "Simulated error",
                )))
            });
        }));

        repository_add_folder(&client, folder_id, "old_name").await;

        let result = client
            .edit(
                folder_id,
                FolderAddEditRequest {
                    name: "test".to_string(),
                },
            )
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EditFolderError::Api(_)));
    }
}

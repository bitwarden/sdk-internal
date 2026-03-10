use std::sync::Arc;

use bitwarden_core::{FromClient, require};
use bitwarden_state::repository::Repository;
use bitwarden_sync::{SyncHandler, SyncHandlerError};

use crate::{Folder, FolderId};

/// Sync handler for folders
///
/// This handler persists folders to SDK-managed storage.
#[derive(FromClient)]
pub struct FolderSyncHandler {
    repository: Arc<dyn Repository<Folder>>,
}

#[async_trait::async_trait]
impl SyncHandler for FolderSyncHandler {
    async fn on_sync(
        &self,
        response: &bitwarden_api_api::models::SyncResponseModel,
    ) -> Result<(), SyncHandlerError> {
        let api_folders = require!(response.folders.as_ref());

        let folders: Vec<(FolderId, Folder)> = api_folders
            .iter()
            .filter_map(|f| {
                Folder::try_from(f.clone())
                    .inspect_err(
                        |e| tracing::error!(id = ?f.id, error = ?e, "Failed to deserialize folder"),
                    )
                    .ok()
                    .and_then(|folder| {
                        let id = folder.id.or_else(|| {
                            tracing::error!("Skipping folder with missing id");
                            None
                        })?;
                        Some((id, folder))
                    })
            })
            .collect();

        self.repository.replace_all(folders).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bitwarden_api_api::models::{FolderResponseModel, SyncResponseModel};
    use bitwarden_test::MemoryRepository;

    use super::*;

    /// Valid EncString in type 2 format (Aes256CbcHmac): `2.<iv>|<data>|<mac>`
    const ENCRYPTED_NAME: &str = "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn make_folder_response(id: uuid::Uuid) -> FolderResponseModel {
        FolderResponseModel {
            object: Some("folder".to_string()),
            id: Some(id),
            name: Some(ENCRYPTED_NAME.to_string()),
            revision_date: Some("2025-01-01T00:00:00Z".to_string()),
        }
    }

    #[tokio::test]
    async fn test_on_sync_replaces_existing_folders() {
        let repository = Arc::new(MemoryRepository::<Folder>::default());
        let handler = FolderSyncHandler {
            repository: repository.clone(),
        };

        // First sync with two folders
        let id1 = uuid::Uuid::new_v4();
        let id2 = uuid::Uuid::new_v4();
        let response = SyncResponseModel {
            folders: Some(vec![make_folder_response(id1), make_folder_response(id2)]),
            ..Default::default()
        };
        handler.on_sync(&response).await.unwrap();
        assert_eq!(repository.list().await.unwrap().len(), 2);

        // Second sync with only one folder — old ones should be gone
        let id3 = uuid::Uuid::new_v4();
        let response = SyncResponseModel {
            folders: Some(vec![make_folder_response(id3)]),
            ..Default::default()
        };
        handler.on_sync(&response).await.unwrap();

        let stored = repository.list().await.unwrap();
        assert_eq!(stored.len(), 1);
        assert!(repository.get(FolderId::new(id1)).await.unwrap().is_none());
        assert!(repository.get(FolderId::new(id2)).await.unwrap().is_none());
        assert!(repository.get(FolderId::new(id3)).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_on_sync_no_folders_returns_error() {
        let repository = Arc::new(MemoryRepository::<Folder>::default());
        let handler = FolderSyncHandler {
            repository: repository.clone(),
        };

        let response = SyncResponseModel::default();
        let result = handler.on_sync(&response).await;
        assert!(result.is_err());
    }
}

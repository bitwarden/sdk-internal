use std::collections::HashMap;

use bitwarden_core::{Client, require};
use bitwarden_state::repository::Repository;
use bitwarden_sync::{SyncEventHandler, SyncHandlerError};

use crate::{Folder, FolderId};

/// Sync handler for folders
///
/// This handler persists folders to SDK-managed storage, comparing
/// revision dates to avoid unnecessary writes and handling deletions.
pub struct FolderSyncHandler {
    client: Client,
}

impl FolderSyncHandler {
    /// Create a new FolderSyncHandler
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl SyncEventHandler for FolderSyncHandler {
    async fn on_sync_complete(
        &self,
        response: &bitwarden_api_api::models::SyncResponseModel,
    ) -> Result<(), SyncHandlerError> {
        let state = self.client.platform().state();
        let repo = state.get_sdk_managed::<Folder>()?;

        // Build a map of existing folders by ID for efficient lookups
        let mut existing_folders: HashMap<FolderId, Folder> = repo
            .list()
            .await?
            .into_iter()
            .filter_map(|folder| folder.id.map(|id| (id, folder)))
            .collect();

        let api_folders = require!(response.folders.as_ref());
        for folder_response in api_folders {
            let folder = Folder::try_from(folder_response.clone())?;

            // Skip folders without IDs (invalid state)
            let folder_id = require!(folder.id);

            // Only save if folder is new or has been updated
            let needs_update = existing_folders
                .get(&folder_id)
                .is_none_or(|existing| folder.revision_date > existing.revision_date);

            if needs_update {
                repo.set(folder_id.to_string(), folder).await?;
            }

            // Mark as processed (remaining entries will be deleted)
            existing_folders.remove(&folder_id);
        }

        // Delete folders that were not in the sync response
        for (id, _) in existing_folders {
            repo.remove(id.to_string()).await?;
        }

        Ok(())
    }
}

use std::collections::HashMap;

use bitwarden_core::{Client, require};
use bitwarden_sync::{SyncHandler, SyncHandlerError};

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
impl SyncHandler for FolderSyncHandler {
    async fn on_sync_complete(
        &self,
        response: &bitwarden_api_api::models::SyncResponseModel,
    ) -> Result<(), SyncHandlerError> {
        let state = self.client.platform().state();
        let repo = state.get::<Folder>()?;

        // Get existing folders for revision_date comparison
        let mut existing: HashMap<FolderId, Folder> = repo
            .list()
            .await?
            .into_iter()
            .filter_map(|folder| folder.id.map(|id| (id, folder)))
            .collect();

        let api_folders = require!(response.folders.as_ref());

        // Convert and validate all folders first (fail fast if any conversion fails)
        // This ensures atomicity - either all conversions succeed or none are persisted
        let mut folders_to_update = Vec::new();
        for folder_response in api_folders {
            let folder = Folder::try_from(folder_response.clone())?;
            let folder_id = require!(folder.id);

            // Check if folder needs to be updated
            let needs_update = existing
                .get(&folder_id)
                .is_none_or(|existing_folder| folder.revision_date > existing_folder.revision_date);

            if needs_update {
                folders_to_update.push((folder_id, folder));
            }

            // Mark as processed (remaining entries in map will be deleted)
            existing.remove(&folder_id);
        }

        // TODO: Replace with bulk operations when supported
        for (id, folder) in folders_to_update {
            repo.set(id.to_string(), folder).await?;
        }

        // TODO: Replace with bulk operations when supported
        for (id, _) in existing {
            repo.remove(id.to_string()).await?;
        }

        Ok(())
    }
}

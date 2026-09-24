use std::sync::Arc;

use bitwarden_core::{FromClient, require};
use bitwarden_state::repository::{Repository, RepositoryOption};
use bitwarden_sync::{SyncHandler, SyncHandlerError};

use crate::{Cipher, CipherId};

/// Sync handler for ciphers (vault items)
///
/// This handler persists ciphers to SDK-managed storage. Modeled on `FolderSyncHandler`.
#[derive(FromClient)]
pub struct CipherSyncHandler {
    repository: Option<Arc<dyn Repository<Cipher>>>,
}

#[async_trait::async_trait]
impl SyncHandler for CipherSyncHandler {
    async fn on_sync(
        &self,
        response: &bitwarden_api_api::models::SyncResponseModel,
    ) -> Result<(), SyncHandlerError> {
        let repository = self.repository.require()?;
        let api_ciphers = require!(response.ciphers.as_ref());

        let ciphers: Vec<(CipherId, Cipher)> = api_ciphers
            .iter()
            .filter_map(|c| {
                Cipher::try_from(c.clone())
                    .inspect_err(
                        |e| tracing::error!(id = ?c.id, error = ?e, "Failed to deserialize cipher"),
                    )
                    .ok()
                    .and_then(|cipher| {
                        let id = cipher.id.or_else(|| {
                            tracing::error!("Skipping cipher with missing id");
                            None
                        })?;
                        Some((id, cipher))
                    })
            })
            .collect();

        repository.replace_all(ciphers).await?;

        Ok(())
    }
}
use std::sync::Arc;

use bitwarden_api_api::models::SyncResponseModel;
use bitwarden_core::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::{SyncHandler, SyncHandlerError, SyncRegistry};

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum SyncError {
    #[error(transparent)]
    Api(#[from] bitwarden_core::ApiError),

    #[error("Sync event handler failed: {0}")]
    HandlerFailed(#[source] SyncHandlerError),
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SyncRequest {
    /// Exclude the subdomains from the response, defaults to false
    pub exclude_subdomains: Option<bool>,
}

/// Client for performing sync operations with event support
///
/// This client wraps the core sync functionality and provides hooks
/// for registering event handlers that can respond to sync operations.
pub struct SyncClient {
    client: Client,
    registry: Arc<SyncRegistry>,
    sync_lock: Mutex<()>,
}

impl SyncClient {
    /// Create a new SyncClient from a Bitwarden client
    pub fn new(client: Client) -> Self {
        Self {
            client,
            registry: Arc::new(SyncRegistry::new()),
            sync_lock: Mutex::new(()),
        }
    }

    /// Register an event handler for sync operations
    ///
    /// Handlers are called in registration order. If any handler returns an error,
    /// the sync operation is aborted immediately and subsequent handlers are not called.
    pub fn register_handler(&self, handler: Arc<dyn SyncHandler>) {
        self.registry.register(handler);
    }

    /// Perform a full sync operation
    ///
    /// This method:
    /// 1. Performs the sync with the Bitwarden API
    /// 2. On success, dispatches `on_sync` with the sync response to all registered handlers
    /// 3. Dispatches `on_sync_complete` to all handlers for post-processing
    ///
    /// Handlers receive the raw API models and are responsible for converting to domain types
    /// as needed. This allows each handler to decide how to process the data.
    ///
    /// If any handler returns an error, the operation is aborted immediately.
    pub async fn sync(&self, request: SyncRequest) -> Result<SyncResponseModel, SyncError> {
        // Wait for any in-progress sync to complete before starting a new one
        let _guard = self.sync_lock.lock().await;

        // Perform actual sync
        let response = perform_sync(&self.client, &request).await?;

        // Trigger sync handlers (on_sync + on_sync_complete phases)
        self.registry.trigger_sync(&response).await?;

        Ok(response)
    }
}

/// Extension trait to add sync() method to Client
///
/// This trait provides a convenient way to create a SyncClient from
/// a Bitwarden Client instance.
pub trait SyncClientExt {
    /// Create a new SyncClient for this client
    fn sync(&self) -> SyncClient;
}

impl SyncClientExt for Client {
    fn sync(&self) -> SyncClient {
        SyncClient::new(self.clone())
    }
}

/// Performs the actual sync operation with the Bitwarden API
async fn perform_sync(
    client: &Client,
    input: &SyncRequest,
) -> Result<SyncResponseModel, SyncError> {
    let config = client.internal.get_api_configurations().await;
    let sync = config
        .api_client
        .sync_api()
        .get(input.exclude_subdomains)
        .await
        .map_err(|e| SyncError::Api(e.into()))?;

    Ok(sync)
}

#[cfg(test)]
mod tests {
    use tokio::sync::Mutex;

    #[tokio::test]
    async fn test_sync_lock_serializes_access() {
        let lock = Mutex::new(());
        let _guard = lock.lock().await;

        // Lock is held, try_lock should fail
        assert!(lock.try_lock().is_err());
    }

    #[tokio::test]
    async fn test_sync_lock_releases_after_drop() {
        let lock = Mutex::new(());
        {
            let _guard = lock.lock().await;
            assert!(lock.try_lock().is_err());
        }
        // Lock is released, should be acquirable again
        assert!(lock.try_lock().is_ok());
    }
}

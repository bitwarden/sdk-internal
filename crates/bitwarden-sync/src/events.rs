//! Event system for sync operations
//!
//! This module provides a trait-based event system that allows other crates
//! to respond to sync operations by implementing the `SyncEventHandler` trait.

use std::sync::{Arc, RwLock};

use bitwarden_api_api::models::SyncResponseModel;

use crate::SyncError;

/// Type alias for sync handler error results
pub type SyncHandlerError = Box<dyn std::error::Error + Send + Sync>;

/// Trait for handling sync events
///
/// Implementors can register themselves with a SyncClient to receive notifications
/// when sync operations complete successfully. All handlers are called sequentially
/// in registration order.
///
/// If any handler returns an error, subsequent handlers are not called and the
/// error is propagated to the caller.
#[async_trait::async_trait]
pub trait SyncEventHandler: Send + Sync {
    /// Called after a successful sync operation
    ///
    /// The sync response contains raw API models from the server. Handlers are responsible
    /// for converting these to domain types as needed and persisting data to local storage.
    async fn on_sync_complete(&self, response: &SyncResponseModel) -> Result<(), SyncHandlerError>;
}

/// Registry for managing sync event handlers
///
/// Handlers are called sequentially in the order they were registered.
/// If any handler fails, execution stops immediately and the error is propagated.
pub struct SyncEventRegistry {
    handlers: Arc<RwLock<Vec<Arc<dyn SyncEventHandler>>>>,
}

impl SyncEventRegistry {
    /// Create a new empty event registry
    pub fn new() -> Self {
        Self {
            handlers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Register a new event handler
    ///
    /// Handlers are called in registration order during sync operations.
    pub fn register(&self, handler: Arc<dyn SyncEventHandler>) {
        self.handlers
            .write()
            .expect("Handler registry lock poisoned")
            .push(handler);
    }

    /// Trigger on_sync_complete for all registered handlers
    ///
    /// Stops on first error and returns it immediately.
    pub async fn trigger_sync_complete(
        &self,
        response: &SyncResponseModel,
    ) -> Result<(), SyncError> {
        let handlers = self
            .handlers
            .read()
            .expect("Handler registry lock poisoned")
            .clone();

        for handler in handlers {
            handler
                .on_sync_complete(response)
                .await
                .map_err(SyncError::HandlerFailed)?;
        }

        Ok(())
    }
}

impl Default for SyncEventRegistry {
    fn default() -> Self {
        Self::new()
    }
}

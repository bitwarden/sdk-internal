//! Event system for sync operations
//!
//! This module provides a trait-based event system that allows other crates
//! to respond to sync operations by implementing the [`SyncHandler`] trait
//! and to handle sync errors via the [`SyncErrorHandler`] trait.

use bitwarden_api_api::models::SyncResponseModel;

use crate::SyncError;

/// Type alias for sync handler error results
pub type SyncHandlerError = Box<dyn std::error::Error + Send + Sync>;

/// Trait for handling sync events
///
/// Implementors can register themselves with a SyncClient to receive notifications
/// about sync operations. All handlers are called sequentially in registration order.
///
/// The sync lifecycle has two phases:
/// 1. [`on_sync`](SyncHandler::on_sync) — called with the raw API response for data processing
/// 2. [`on_sync_complete`](SyncHandler::on_sync_complete) — called after all handlers have finished
///    `on_sync`, for post-processing work
///
/// If any handler returns an error, subsequent handlers are not called and the
/// error is propagated to the caller.
#[async_trait::async_trait]
pub trait SyncHandler: Send + Sync {
    /// Called after a successful sync operation
    ///
    /// The sync response contains raw API models from the server. Handlers are responsible
    /// for converting these to domain types as needed and persisting data to local storage.
    async fn on_sync(&self, response: &SyncResponseModel) -> Result<(), SyncHandlerError>;

    /// Called after all handlers have finished processing [`on_sync`](SyncHandler::on_sync)
    ///
    /// Override this method to perform post-processing work that should happen after all
    /// handlers have persisted their data. The default implementation is a no-op.
    async fn on_sync_complete(&self) {}
}

/// Trait for handling errors that occur during sync operations
///
/// Error handlers are called when the sync operation fails, either due to
/// an API error or a sync handler error.
///
/// Error handlers are called sequentially in registration order while the
/// sync lock is still held. Implementations should avoid long-running operations
/// and must not call [`SyncClient::sync`](crate::SyncClient::sync) (which would deadlock).
#[async_trait::async_trait]
pub trait SyncErrorHandler: Send + Sync {
    /// Called when a sync operation encounters an error
    ///
    /// The `error` parameter contains the [`SyncError`] that caused
    /// the sync to fail. This could be an API error or a handler processing error.
    async fn on_error(&self, error: &SyncError);
}

//! Event system for sync operations
//!
//! This module provides a trait-based event system that allows other crates
//! to respond to sync operations by implementing the `SyncEventHandler` trait.

use bitwarden_api_api::models::SyncResponseModel;

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
pub trait SyncHandler: Send + Sync {
    /// Called after a successful sync operation
    ///
    /// The sync response contains raw API models from the server. Handlers are responsible
    /// for converting these to domain types as needed and persisting data to local storage.
    async fn on_sync_complete(&self, response: &SyncResponseModel) -> Result<(), SyncHandlerError>;
}

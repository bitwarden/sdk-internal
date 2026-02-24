//! Registry for managing sync handlers.
//!
//! This module provides [`SyncRegistry`], a thread-safe registry that manages
//! [`SyncHandler`] implementations. The registry follows an observer pattern,
//! allowing multiple handlers to be notified when sync operations complete.
//!
//! # Architecture
//!
//! The registry uses interior mutability via `Arc<RwLock<...>>` to allow
//! handler registration without requiring mutable access. This enables
//! sharing the registry across async boundaries and multiple components.
//!
//! # Execution Model
//!
//! Handlers are executed **sequentially** in registration order. This design:
//! - Provides predictable, deterministic execution
//! - Allows handlers to depend on side effects from earlier handlers
//! - Simplifies error handling with fail-fast semantics
//!
//! If any handler returns an error, execution stops immediately and the error
//! is propagated to the caller. Subsequent handlers are **not** called.
//!
//! # Example
//!
//! ```ignore
//! use std::sync::Arc;
//! use bitwarden_sync::{SyncRegistry, SyncHandler};
//!
//! let registry = SyncRegistry::new();
//!
//! // Register handlers - they will be called in this order
//! registry.register(Arc::new(FolderSyncHandler::new()));
//! registry.register(Arc::new(CipherSyncHandler::new()));
//!
//! // Later, during sync:
//! registry.trigger_sync(&response).await?;
//! ```

use std::sync::{Arc, RwLock};

use bitwarden_api_api::models::SyncResponseModel;

use crate::{SyncError, SyncHandler};

/// Registry for managing sync event handlers
///
/// Handlers are called sequentially in the order they were registered.
/// If any handler fails, execution stops immediately and the error is propagated.
#[derive(Default)]
pub struct SyncRegistry {
    handlers: Arc<RwLock<Vec<Arc<dyn SyncHandler>>>>,
}

impl SyncRegistry {
    /// Create a new empty event registry
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new event handler
    ///
    /// Handlers are called in registration order during sync operations.
    pub fn register(&self, handler: Arc<dyn SyncHandler>) {
        self.handlers
            .write()
            .expect("Handler registry lock poisoned")
            .push(handler);
    }

    /// Trigger sync handlers for a completed sync operation
    ///
    /// Executes two phases sequentially:
    /// 1. Calls [`SyncHandler::on_sync`] on all handlers with the response
    /// 2. Calls [`SyncHandler::on_sync_complete`] on all handlers
    ///
    /// Stops on first error and returns it immediately.
    pub async fn trigger_sync(&self, response: &SyncResponseModel) -> Result<(), SyncError> {
        let handlers = self
            .handlers
            .read()
            .expect("Handler registry lock poisoned")
            .clone();

        for handler in &handlers {
            handler
                .on_sync(response)
                .await
                .map_err(SyncError::HandlerFailed)?;
        }

        for handler in &handlers {
            handler.on_sync_complete().await;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::SyncHandlerError;

    struct TestHandler {
        name: String,
        execution_log: Arc<Mutex<Vec<String>>>,
        should_fail: bool,
    }

    #[async_trait::async_trait]
    impl SyncHandler for TestHandler {
        async fn on_sync(&self, _response: &SyncResponseModel) -> Result<(), SyncHandlerError> {
            self.execution_log.lock().unwrap().push(self.name.clone());
            if self.should_fail {
                Err("Handler failed".into())
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn test_handlers_execute_in_registration_order() {
        let registry = SyncRegistry::new();
        let log = Arc::new(Mutex::new(Vec::new()));

        registry.register(Arc::new(TestHandler {
            name: "first".to_string(),
            execution_log: log.clone(),
            should_fail: false,
        }));
        registry.register(Arc::new(TestHandler {
            name: "second".to_string(),
            execution_log: log.clone(),
            should_fail: false,
        }));
        registry.register(Arc::new(TestHandler {
            name: "third".to_string(),
            execution_log: log.clone(),
            should_fail: false,
        }));

        let response = SyncResponseModel::default();
        registry.trigger_sync(&response).await.unwrap();

        assert_eq!(
            *log.lock().unwrap(),
            vec!["first", "second", "third"],
            "Handlers should execute in registration order"
        );
    }

    #[tokio::test]
    async fn test_handler_error_stops_subsequent_handlers() {
        let registry = SyncRegistry::new();
        let log = Arc::new(Mutex::new(Vec::new()));

        registry.register(Arc::new(TestHandler {
            name: "first".to_string(),
            execution_log: log.clone(),
            should_fail: false,
        }));
        registry.register(Arc::new(TestHandler {
            name: "second".to_string(),
            execution_log: log.clone(),
            should_fail: true,
        }));
        registry.register(Arc::new(TestHandler {
            name: "third".to_string(),
            execution_log: log.clone(),
            should_fail: false,
        }));

        let response = SyncResponseModel::default();
        let result = registry.trigger_sync(&response).await;

        assert!(
            result.is_err(),
            "Registry should return error when handler fails"
        );
        assert_eq!(
            *log.lock().unwrap(),
            vec!["first", "second"],
            "Third handler should not execute after second handler fails"
        );
    }

    #[tokio::test]
    async fn test_empty_registry_succeeds() {
        let registry = SyncRegistry::new();
        let response = SyncResponseModel::default();

        let result = registry.trigger_sync(&response).await;

        assert!(
            result.is_ok(),
            "Empty registry should succeed without errors"
        );
    }

    #[tokio::test]
    async fn test_single_handler_success() {
        let registry = SyncRegistry::new();
        let log = Arc::new(Mutex::new(Vec::new()));

        registry.register(Arc::new(TestHandler {
            name: "only".to_string(),
            execution_log: log.clone(),
            should_fail: false,
        }));

        let response = SyncResponseModel::default();
        registry.trigger_sync(&response).await.unwrap();

        assert_eq!(
            *log.lock().unwrap(),
            vec!["only"],
            "Single handler should execute successfully"
        );
    }

    #[tokio::test]
    async fn test_single_handler_failure() {
        let registry = SyncRegistry::new();
        let log = Arc::new(Mutex::new(Vec::new()));

        registry.register(Arc::new(TestHandler {
            name: "only".to_string(),
            execution_log: log.clone(),
            should_fail: true,
        }));

        let response = SyncResponseModel::default();
        let result = registry.trigger_sync(&response).await;

        assert!(result.is_err(), "Should propagate handler failure");
        assert_eq!(
            *log.lock().unwrap(),
            vec!["only"],
            "Failed handler should have been called"
        );
    }
}

use std::sync::Arc;

use bitwarden_api_api::models::SyncResponseModel;
use bitwarden_core::{
    Client,
    client::{ApiConfigurations, FromClientPart},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::{SyncErrorHandler, SyncHandler, SyncHandlerError, registry::HandlerRegistry};

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
    api_configurations: Arc<ApiConfigurations>,
    sync_handlers: HandlerRegistry<dyn SyncHandler>,
    error_handlers: HandlerRegistry<dyn SyncErrorHandler>,
    sync_lock: Mutex<()>,
}

impl SyncClient {
    /// Create a new SyncClient from a Bitwarden client
    pub fn new(client: Client) -> Self {
        Self {
            api_configurations: client
                .get_part()
                .expect("ApiConfigurations should never fail"),
            sync_handlers: HandlerRegistry::new(),
            error_handlers: HandlerRegistry::new(),
            sync_lock: Mutex::new(()),
        }
    }

    /// Register a sync handler for sync operations
    ///
    /// Handlers are called in registration order. If any handler returns an error,
    /// the sync operation is aborted immediately and subsequent handlers are not called.
    pub fn register_sync_handler(&self, handler: Arc<dyn SyncHandler>) {
        self.sync_handlers.register(handler);
    }

    /// Register an error handler for sync operations
    ///
    /// Error handlers are called when any error occurs during sync, including
    /// API errors and handler errors. All error handlers are always called
    /// regardless of individual failures.
    pub fn register_error_handler(&self, handler: Arc<dyn SyncErrorHandler>) {
        self.error_handlers.register(handler);
    }

    /// Perform a full sync operation
    ///
    /// This method:
    /// 1. Performs the sync with the Bitwarden API
    /// 2. On success, dispatches `on_sync` with the sync response to all registered handlers
    /// 3. Dispatches `on_sync_complete` to all handlers for post-processing
    /// 4. On error (from API or handlers), notifies all registered error handlers
    ///
    /// Handlers receive the raw API models and are responsible for converting to domain types
    /// as needed. This allows each handler to decide how to process the data.
    ///
    /// If any error occurs, all registered error handlers are notified before
    /// the error is returned to the caller.
    pub async fn sync(&self, request: SyncRequest) -> Result<SyncResponseModel, SyncError> {
        // Wait for any in-progress sync to complete before starting a new one
        let _guard = self.sync_lock.lock().await;

        let result = async {
            let response = perform_sync(&self.api_configurations, &request).await?;
            self.trigger_sync(&response).await?;
            Ok(response)
        }
        .await;

        if let Err(ref error) = result {
            self.notify_error(error).await;
        }

        result
    }

    /// Trigger sync handlers for a completed sync operation
    ///
    /// Executes two phases sequentially:
    /// 1. Calls [`SyncHandler::on_sync`] on all handlers with the response
    /// 2. Calls [`SyncHandler::on_sync_complete`] on all handlers
    ///
    /// Stops on first error and returns it immediately.
    async fn trigger_sync(&self, response: &SyncResponseModel) -> Result<(), SyncError> {
        let handlers = self.sync_handlers.handlers();

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

    /// Notify all error handlers about a sync error
    ///
    /// All error handlers are called sequentially in registration order.
    async fn notify_error(&self, error: &SyncError) {
        for handler in &self.error_handlers.handlers() {
            handler.on_error(error).await;
        }
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
    api_configurations: &Arc<ApiConfigurations>,
    input: &SyncRequest,
) -> Result<SyncResponseModel, SyncError> {
    let sync = api_configurations
        .api_client
        .sync_api()
        .get(input.exclude_subdomains)
        .await
        .map_err(|e| SyncError::Api(e.into()))?;

    Ok(sync)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

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

    struct TestErrorHandler {
        name: String,
        error_log: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait::async_trait]
    impl SyncErrorHandler for TestErrorHandler {
        async fn on_error(&self, _error: &SyncError) {
            self.error_log.lock().unwrap().push(self.name.clone());
        }
    }

    /// Helper to create a SyncClient with a mocked API client.
    fn test_client(api_client: bitwarden_api_api::apis::ApiClient) -> SyncClient {
        let dummy_config = bitwarden_api_api::Configuration {
            base_path: String::new(),
            client: reqwest_middleware::ClientBuilder::new(reqwest::Client::new()).build(),
            oauth_access_token: None,
            user_agent: None,
        };
        SyncClient {
            api_configurations: Arc::new(ApiConfigurations {
                api_client,
                identity_client: bitwarden_api_identity::apis::ApiClient::new_mocked(|_| {}),
                api_config: dummy_config.clone(),
                identity_config: dummy_config,
                device_type: bitwarden_core::client::DeviceType::SDK,
            }),
            sync_handlers: HandlerRegistry::new(),
            error_handlers: HandlerRegistry::new(),
            sync_lock: tokio::sync::Mutex::new(()),
        }
    }

    #[tokio::test]
    async fn test_handlers_execute_in_registration_order() {
        let client = test_client(bitwarden_api_api::apis::ApiClient::new_mocked(|_| {}));
        let log = Arc::new(Mutex::new(Vec::new()));

        client.register_sync_handler(Arc::new(TestHandler {
            name: "first".to_string(),
            execution_log: log.clone(),
            should_fail: false,
        }));
        client.register_sync_handler(Arc::new(TestHandler {
            name: "second".to_string(),
            execution_log: log.clone(),
            should_fail: false,
        }));
        client.register_sync_handler(Arc::new(TestHandler {
            name: "third".to_string(),
            execution_log: log.clone(),
            should_fail: false,
        }));

        let response = SyncResponseModel::default();
        client.trigger_sync(&response).await.unwrap();

        assert_eq!(
            *log.lock().unwrap(),
            vec!["first", "second", "third"],
            "Handlers should execute in registration order"
        );
    }

    #[tokio::test]
    async fn test_handler_error_stops_subsequent_handlers() {
        let client = test_client(bitwarden_api_api::apis::ApiClient::new_mocked(|_| {}));
        let log = Arc::new(Mutex::new(Vec::new()));

        client.register_sync_handler(Arc::new(TestHandler {
            name: "first".to_string(),
            execution_log: log.clone(),
            should_fail: false,
        }));
        client.register_sync_handler(Arc::new(TestHandler {
            name: "second".to_string(),
            execution_log: log.clone(),
            should_fail: true,
        }));
        client.register_sync_handler(Arc::new(TestHandler {
            name: "third".to_string(),
            execution_log: log.clone(),
            should_fail: false,
        }));

        let response = SyncResponseModel::default();
        let result = client.trigger_sync(&response).await;

        assert!(result.is_err(), "Should return error when handler fails");
        assert_eq!(
            *log.lock().unwrap(),
            vec!["first", "second"],
            "Third handler should not execute after second handler fails"
        );
    }

    #[tokio::test]
    async fn test_sync_error_notifies_error_handlers() {
        let client = test_client(bitwarden_api_api::apis::ApiClient::new_mocked(|mock| {
            mock.sync_api.expect_get().returning(|_| {
                Err(bitwarden_api_api::Error::Io(std::io::Error::other(
                    "test error",
                )))
            });
        }));
        let error_log = Arc::new(Mutex::new(Vec::new()));

        client.register_error_handler(Arc::new(TestErrorHandler {
            name: "first".to_string(),
            error_log: error_log.clone(),
        }));
        client.register_error_handler(Arc::new(TestErrorHandler {
            name: "second".to_string(),
            error_log: error_log.clone(),
        }));

        // sync() will fail due to the mocked error, which should trigger all error handlers
        let result = client
            .sync(SyncRequest {
                exclude_subdomains: None,
            })
            .await;

        assert!(result.is_err());
        assert_eq!(
            *error_log.lock().unwrap(),
            vec!["first", "second"],
            "All error handlers should be called on sync failure"
        );
    }
}

use std::sync::Arc;

use bitwarden_api_api::models::SyncResponseModel;
use bitwarden_core::{
    Client,
    client::{ApiConfigurations, FromClientPart},
};
use bitwarden_state::Setting;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::{
    SyncErrorHandler, SyncHandler, SyncHandlerError, registry::HandlerRegistry, state::LAST_SYNC,
};

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum SyncError {
    #[error(transparent)]
    Api(#[from] bitwarden_core::ApiError),

    #[error("Sync event handler failed: {0}")]
    HandlerFailed(#[source] SyncHandlerError),

    #[error("Account has been deleted on the server.")]
    AccountDeleted,

    #[error(transparent)]
    Setting(#[from] bitwarden_state::SettingsError),

    #[error("Server returned an unrepresentable revision date.")]
    InvalidRevisionDate,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SyncRequest {
    /// Skip the revision-date check and always sync.
    #[serde(default)]
    pub force: bool,
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
    last_sync: Option<Setting<DateTime<Utc>>>,
}

impl SyncClient {
    /// Create a new SyncClient from a Bitwarden client
    pub fn new(client: Client) -> Self {
        Self {
            api_configurations: client.get_part(),
            sync_handlers: HandlerRegistry::new(),
            error_handlers: HandlerRegistry::new(),
            sync_lock: Mutex::new(()),
            last_sync: client.platform().state().setting(LAST_SYNC).ok(),
        }
    }

    /// Get the timestamp of the last successful sync or confirmed-up-to-date skip, if any.
    pub async fn last_sync(&self) -> Option<DateTime<Utc>> {
        match self.last_sync.as_ref()?.get().await {
            Ok(value) => value,
            Err(e) => {
                tracing::warn!("Failed to read last sync timestamp: {e}");
                None
            }
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

    /// Perform a sync operation, skipping the server call when nothing has changed.
    ///
    /// Returns `Ok(true)` if a full sync was performed, or `Ok(false)` if the revision-date
    /// check determined that the server has no new changes and the sync was skipped.
    ///
    /// ## Control flow
    ///
    /// Unless `request.force` is `true`, this method first fetches the account revision date
    /// from the server and compares it to the stored `last_sync` timestamp. If the revision
    /// is not newer, the sync is skipped: `last_sync` is bumped to now and `Ok(false)` is
    /// returned without calling any sync or error handlers.
    ///
    /// When a full sync is performed:
    /// 1. Fetches the full sync response from the Bitwarden API.
    /// 2. Dispatches `on_sync` with the response to all registered handlers in order; stops on the
    ///    first handler error.
    /// 3. Dispatches `on_sync_complete` to all handlers for post-processing.
    /// 4. On success, bumps `last_sync` to now and returns `Ok(true)`.
    ///
    /// ## Errors
    ///
    /// Any error (revision-date fetch, API call, or handler failure) is forwarded to all
    /// registered error handlers before being returned to the caller. `last_sync` is never
    /// bumped on an error path.
    pub async fn sync(&self, request: SyncRequest) -> Result<bool, SyncError> {
        // Wait for any in-progress sync to complete before starting a new one
        let _guard = self.sync_lock.lock().await;

        let needs_sync = if request.force {
            true
        } else {
            match self.needs_sync().await {
                Ok(needed) => needed,
                Err(e) => {
                    self.run_error_handlers(&e).await;
                    return Err(e);
                }
            }
        };

        if !needs_sync {
            // Persistent clock-skew note: if the local clock is permanently ahead of the
            // server, every revision check will say "no sync needed" and we keep bumping
            // lastSync to a future-skewed `now` — server-side changes are never picked up
            // until the clock is corrected. Matches Node CLI behaviour.
            self.update_last_sync(Utc::now()).await;
            return Ok(false);
        }

        let result = async {
            let response = self.perform_sync(&request).await?;
            self.run_handlers(&response).await?;
            Ok(response)
        }
        .await;

        match result {
            Ok(_) => {
                self.update_last_sync(Utc::now()).await;
                Ok(true)
            }
            Err(error) => {
                self.run_error_handlers(&error).await;
                Err(error)
            }
        }
    }

    async fn needs_sync(&self) -> Result<bool, SyncError> {
        let Some(last_sync_setting) = self.last_sync.as_ref() else {
            return Ok(true); // No state backend — always sync
        };
        let Some(last_sync) = last_sync_setting.get().await? else {
            return Ok(true); // First sync — skip revision check
        };

        let revision_ms = self
            .api_configurations
            .api_client
            .accounts_api()
            .get_account_revision_date()
            .await
            .map_err(|e| SyncError::Api(e.into()))?;

        if revision_ms < 0 {
            return Err(SyncError::AccountDeleted);
        }

        Ok(DateTime::<Utc>::from_timestamp_millis(revision_ms)
            .ok_or(SyncError::InvalidRevisionDate)?
            > last_sync)
    }

    async fn update_last_sync(&self, now: DateTime<Utc>) {
        if let Some(setting) = self.last_sync.as_ref()
            && let Err(e) = setting.update(now).await
        {
            tracing::warn!("Failed to update last sync timestamp: {e}");
        }
    }

    /// Run sync handlers for a completed sync operation
    ///
    /// Executes two phases sequentially:
    /// 1. Calls [`SyncHandler::on_sync`] on all handlers with the response
    /// 2. Calls [`SyncHandler::on_sync_complete`] on all handlers
    ///
    /// Stops on first error and returns it immediately.
    async fn run_handlers(&self, response: &SyncResponseModel) -> Result<(), SyncError> {
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

    /// Run all error handlers for a sync error
    ///
    /// All error handlers are called sequentially in registration order.
    async fn run_error_handlers(&self, error: &SyncError) {
        for handler in &self.error_handlers.handlers() {
            handler.on_error(error).await;
        }
    }

    /// Performs the actual sync operation with the Bitwarden API
    async fn perform_sync(&self, input: &SyncRequest) -> Result<SyncResponseModel, SyncError> {
        let sync = self
            .api_configurations
            .api_client
            .sync_api()
            .get(input.exclude_subdomains)
            .await
            .map_err(|e| SyncError::Api(e.into()))?;

        Ok(sync)
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

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use chrono::{Duration, Utc};

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
        let dummy_config = bitwarden_api_api::Configuration::new(String::new());
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
            last_sync: None,
        }
    }

    /// Helper to create a SyncClient with a state-backed last_sync setting.
    ///
    /// If `stored_last_sync` is `Some`, it is written into the in-memory repository so
    /// that subsequent calls to `needs_sync` see it.
    async fn test_client_with_last_sync(
        api_client: bitwarden_api_api::apis::ApiClient,
        stored_last_sync: Option<DateTime<Utc>>,
    ) -> SyncClient {
        let repo: Arc<dyn bitwarden_state::repository::Repository<bitwarden_state::SettingItem>> =
            Arc::new(bitwarden_test::MemoryRepository::<
                bitwarden_state::SettingItem,
            >::default());
        let setting = bitwarden_state::Setting::new(repo, crate::state::LAST_SYNC);
        if let Some(dt) = stored_last_sync {
            setting.update(dt).await.expect("pre-populate last_sync");
        }
        let mut client = test_client(api_client);
        client.last_sync = Some(setting);
        client
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
        client.run_handlers(&response).await.unwrap();

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
        let result = client.run_handlers(&response).await;

        assert!(result.is_err(), "Should return error when handler fails");
        assert_eq!(
            *log.lock().unwrap(),
            vec!["first", "second"],
            "Third handler should not execute after second handler fails"
        );
    }

    #[tokio::test]
    async fn test_sync_success_calls_handlers_and_returns_response() {
        let client = test_client(bitwarden_api_api::apis::ApiClient::new_mocked(|mock| {
            mock.sync_api
                .expect_get()
                .returning(|_| Ok(SyncResponseModel::default()));
        }));
        let sync_log = Arc::new(Mutex::new(Vec::new()));
        let error_log = Arc::new(Mutex::new(Vec::new()));

        client.register_sync_handler(Arc::new(TestHandler {
            name: "handler".to_string(),
            execution_log: sync_log.clone(),
            should_fail: false,
        }));
        client.register_error_handler(Arc::new(TestErrorHandler {
            name: "error_handler".to_string(),
            error_log: error_log.clone(),
        }));

        let result = client
            .sync(SyncRequest {
                force: false,
                exclude_subdomains: None,
            })
            .await;

        assert!(result.is_ok(), "Sync should succeed");
        assert_eq!(
            *sync_log.lock().unwrap(),
            vec!["handler"],
            "Sync handler should be called on success"
        );
        assert!(
            error_log.lock().unwrap().is_empty(),
            "Error handlers should not be called on success"
        );
    }

    #[tokio::test]
    async fn test_sync_error_notifies_error_handlers() {
        let client = test_client(bitwarden_api_api::apis::ApiClient::new_mocked(|mock| {
            mock.sync_api
                .expect_get()
                .returning(|_| Err(std::io::Error::other("test error").into()));
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
                force: false,
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

    #[tokio::test]
    async fn test_first_sync_skips_revision_check() {
        // Setting exists but has no stored value — revision check must not be called.
        let client = test_client_with_last_sync(
            bitwarden_api_api::apis::ApiClient::new_mocked(|mock| {
                mock.sync_api
                    .expect_get()
                    .returning(|_| Ok(SyncResponseModel::default()));
                // accounts_api has no expectation — mock panics on unexpected calls
            }),
            None,
        )
        .await;

        let result = client
            .sync(SyncRequest {
                force: false,
                exclude_subdomains: None,
            })
            .await;

        assert!(result.is_ok_and(|v| v));
    }

    #[tokio::test]
    async fn test_revision_check_skips_sync_when_up_to_date() {
        let stored_last_sync = Utc::now();
        // Server revision is 60 seconds older than our stored last_sync.
        let server_revision_ms = (stored_last_sync - Duration::seconds(60)).timestamp_millis();

        let sync_log = Arc::new(Mutex::new(Vec::<String>::new()));
        let sync_log_clone = sync_log.clone();

        let client = test_client_with_last_sync(
            bitwarden_api_api::apis::ApiClient::new_mocked(move |mock| {
                mock.accounts_api
                    .expect_get_account_revision_date()
                    .returning(move || Ok(server_revision_ms));
                // sync_api has no expectation — must not be called
            }),
            Some(stored_last_sync),
        )
        .await;

        client.register_sync_handler(Arc::new(TestHandler {
            name: "should_not_run".to_string(),
            execution_log: sync_log_clone,
            should_fail: false,
        }));

        let result = client
            .sync(SyncRequest {
                force: false,
                exclude_subdomains: None,
            })
            .await;

        assert!(result.is_ok_and(|v| !v), "Expected Ok(false) skip result");
        assert!(
            sync_log.lock().unwrap().is_empty(),
            "Sync handler must not be called on skip"
        );
    }

    #[tokio::test]
    async fn test_force_bypasses_revision_check() {
        let stored_last_sync = Utc::now();

        let client = test_client_with_last_sync(
            bitwarden_api_api::apis::ApiClient::new_mocked(|mock| {
                mock.sync_api
                    .expect_get()
                    .returning(|_| Ok(SyncResponseModel::default()));
                // accounts_api has no expectation
            }),
            Some(stored_last_sync),
        )
        .await;

        let result = client
            .sync(SyncRequest {
                force: true,
                exclude_subdomains: None,
            })
            .await;

        assert!(result.is_ok_and(|v| v));
    }

    #[tokio::test]
    async fn test_account_deleted_error() {
        let stored_last_sync = Utc::now();
        let error_log = Arc::new(Mutex::new(Vec::<String>::new()));
        let error_log_clone = error_log.clone();

        let client = test_client_with_last_sync(
            bitwarden_api_api::apis::ApiClient::new_mocked(|mock| {
                mock.accounts_api
                    .expect_get_account_revision_date()
                    .returning(|| Ok(-1i64));
            }),
            Some(stored_last_sync),
        )
        .await;

        client.register_error_handler(Arc::new(TestErrorHandler {
            name: "error_handler".to_string(),
            error_log: error_log_clone,
        }));

        let result = client
            .sync(SyncRequest {
                force: false,
                exclude_subdomains: None,
            })
            .await;

        assert!(
            matches!(result, Err(SyncError::AccountDeleted)),
            "Expected AccountDeleted error"
        );
        assert_eq!(
            *error_log.lock().unwrap(),
            vec!["error_handler"],
            "Error handler must be called for AccountDeleted"
        );
    }

    #[tokio::test]
    async fn test_revision_fetch_failure_does_not_bump_last_sync() {
        let stored_last_sync =
            DateTime::<Utc>::from_timestamp_millis(1_000_000).expect("valid timestamp");
        let error_log = Arc::new(Mutex::new(Vec::<String>::new()));
        let error_log_clone = error_log.clone();

        // Build Setting manually so we can inspect it after sync.
        let repo: Arc<dyn bitwarden_state::repository::Repository<bitwarden_state::SettingItem>> =
            Arc::new(bitwarden_test::MemoryRepository::<
                bitwarden_state::SettingItem,
            >::default());
        let setting = bitwarden_state::Setting::new(repo, crate::state::LAST_SYNC);
        setting
            .update(stored_last_sync)
            .await
            .expect("pre-populate last_sync");

        let mut client = test_client(bitwarden_api_api::apis::ApiClient::new_mocked(|mock| {
            mock.accounts_api
                .expect_get_account_revision_date()
                .returning(|| Err(std::io::Error::other("network error").into()));
        }));
        client.last_sync = Some(setting.clone());

        client.register_error_handler(Arc::new(TestErrorHandler {
            name: "error_handler".to_string(),
            error_log: error_log_clone,
        }));

        let result = client
            .sync(SyncRequest {
                force: false,
                exclude_subdomains: None,
            })
            .await;

        assert!(
            result.is_err(),
            "Expected error from revision fetch failure"
        );
        assert_eq!(
            setting.get().await.unwrap(),
            Some(stored_last_sync),
            "last_sync must not be bumped on error"
        );
        assert!(
            !error_log.lock().unwrap().is_empty(),
            "Error handler must be called"
        );
    }
}

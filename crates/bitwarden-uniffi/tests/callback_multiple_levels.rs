//! Integration test validating callback receives multiple log levels.
//!
//! Verifies that the callback mechanism correctly forwards log events at different
//! severity levels (INFO, WARN, ERROR) to the registered callback implementation.

use std::sync::{Arc, Mutex};

use bitwarden_uniffi::*;

// Type alias to match trait definition
type Result<T> = std::result::Result<T, bitwarden_uniffi::error::BitwardenError>;

/// Mock token provider for testing
#[derive(Debug)]
struct MockTokenProvider;

#[async_trait::async_trait]
impl bitwarden_core::client::internal::ClientManagedTokens for MockTokenProvider {
    async fn get_access_token(&self) -> Option<String> {
        Some("mock_token".to_string())
    }
}

/// Test callback that captures logs
struct TestCallback {
    logs: Arc<Mutex<Vec<(String, String, String)>>>,
}

impl LogCallback for TestCallback {
    fn on_log(&self, level: String, target: String, message: String) -> Result<()> {
        self.logs
            .lock()
            .expect("Failed to lock logs mutex")
            .push((level, target, message));
        Ok(())
    }
}

#[test]
fn test_callback_receives_multiple_log_levels() {
    // Verify callback receives events at different log levels
    let logs = Arc::new(Mutex::new(Vec::new()));
    let callback = Arc::new(TestCallback { logs: logs.clone() });

    // Initialize logger with callback
    init_logger(Some(callback));

    let _client = Client::new(Arc::new(MockTokenProvider), None);

    // Emit logs at multiple levels
    tracing::info!("info message");
    tracing::warn!("warn message");
    tracing::error!("error message");

    // Verify all levels captured (tests run in parallel so may have logs from other tests)
    let captured = logs.lock().expect("Failed to lock logs mutex");
    assert!(
        captured.len() >= 3,
        "Should capture at least our 3 log levels"
    );

    // Find our specific log messages
    let info_log = captured
        .iter()
        .find(|(lvl, _, msg)| lvl == "INFO" && msg.contains("info message"))
        .expect("Should find INFO log");

    let warn_log = captured
        .iter()
        .find(|(lvl, _, msg)| lvl == "WARN" && msg.contains("warn message"))
        .expect("Should find WARN log");

    let error_log = captured
        .iter()
        .find(|(lvl, _, msg)| lvl == "ERROR" && msg.contains("error message"))
        .expect("Should find ERROR log");

    // Validate each level
    assert_eq!(info_log.0, "INFO");
    assert!(info_log.2.contains("info message"));

    assert_eq!(warn_log.0, "WARN");
    assert!(warn_log.2.contains("warn message"));

    assert_eq!(error_log.0, "ERROR");
    assert!(error_log.2.contains("error message"));
}

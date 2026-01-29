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

    // Verify all levels captured
    let captured = logs.lock().expect("Failed to lock logs mutex");
    assert_eq!(captured.len(), 3, "Should capture all 3 log levels");

    // Validate each level
    assert_eq!(captured[0].0, "INFO");
    assert!(captured[0].2.contains("info message"));

    assert_eq!(captured[1].0, "WARN");
    assert!(captured[1].2.contains("warn message"));

    assert_eq!(captured[2].0, "ERROR");
    assert!(captured[2].2.contains("error message"));
}

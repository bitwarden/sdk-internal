//! Integration test validating basic callback functionality.
//!
//! Verifies that registered callbacks receive log events with correct data structure
//! including level, target, and message fields.

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

/// Test callback implementation that captures logs
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
fn test_callback_happy_path() {
    // Verify callback receives logs with correct data
    let logs = Arc::new(Mutex::new(Vec::new()));
    let callback = Arc::new(TestCallback { logs: logs.clone() });

    // Initialize logger with callback
    init_logger(Some(callback));

    // Create client
    let _client = Client::new(Arc::new(MockTokenProvider), None);

    // Trigger SDK logging
    tracing::info!("integration test message");

    // Verify callback received the log
    let captured = logs.lock().expect("Failed to lock logs mutex");
    assert!(!captured.is_empty(), "Callback should receive logs");

    // Find our specific log message (tests run in parallel so may have logs from other tests)
    let our_log = captured
        .iter()
        .find(|(_, _, msg)| msg.contains("integration test message"))
        .expect("Should find our integration test message");

    // Validate log data structure
    let (level, target, message) = our_log;
    assert_eq!(level, "INFO", "Log level should be INFO");
    assert!(!target.is_empty(), "Target should not be empty");
    assert!(
        message.contains("integration test message"),
        "Message should contain logged text"
    );
}

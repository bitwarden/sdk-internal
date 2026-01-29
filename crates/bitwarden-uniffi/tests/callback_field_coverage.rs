//! Integration test validating MessageVisitor field extraction.
//!
//! Verifies that the MessageVisitor correctly extracts the message field from
//! tracing events and forwards it through the callback interface.

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
fn test_message_visitor_captures_message_field() {
    // Validate MessageVisitor captures the message field from trace events
    // Note: Structured fields (user_id, valid, etc.) are NOT captured
    // currently. The visitor only extracts the "message" field, not
    // additional structured metadata.
    let logs = Arc::new(Mutex::new(Vec::new()));
    let callback = Arc::new(TestCallback { logs: logs.clone() });

    // Initialize logger with callback
    init_logger(Some(callback));

    let _client = Client::new(Arc::new(MockTokenProvider), None);

    // Emit logs at different levels with message text
    tracing::info!("info message");
    tracing::warn!("warn message");
    tracing::error!("error message");

    let captured = logs.lock().expect("Failed to lock logs mutex");

    // Verify all messages captured
    assert_eq!(captured.len(), 3, "All log entries should be captured");

    // Validate message field extraction
    assert!(
        captured[0].2.contains("info message"),
        "INFO message should be captured, got: {}",
        captured[0].2
    );
    assert!(
        captured[1].2.contains("warn message"),
        "WARN message should be captured, got: {}",
        captured[1].2
    );
    assert!(
        captured[2].2.contains("error message"),
        "ERROR message should be captured, got: {}",
        captured[2].2
    );

    // Validate levels
    assert_eq!(captured[0].0, "INFO");
    assert_eq!(captured[1].0, "WARN");
    assert_eq!(captured[2].0, "ERROR");
}

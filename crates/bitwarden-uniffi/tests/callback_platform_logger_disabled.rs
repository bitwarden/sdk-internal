//! Integration test validating that the callback works with the platform logger disabled.
//!
//! A host that records the callback events itself turns the platform logger off to avoid
//! recording every event twice. Events must still reach the callback.

use std::sync::{Arc, Mutex};

use bitwarden_uniffi::*;

// Type alias to match trait definition
type Result<T> = std::result::Result<T, bitwarden_uniffi::error::BitwardenError>;

/// Mock token provider for testing
#[derive(Debug)]
struct MockTokenProvider;

#[async_trait::async_trait]
impl bitwarden_core::auth::ClientManagedTokens for MockTokenProvider {
    async fn get_access_token(&self) -> Option<String> {
        Some("mock_token".to_string())
    }
}

/// Test callback that captures logs
struct TestCallback {
    logs: Arc<Mutex<Vec<(LogLevel, String, String)>>>,
}

impl LogCallback for TestCallback {
    fn on_log(&self, level: LogLevel, target: String, message: String) -> Result<()> {
        self.logs
            .lock()
            .expect("Failed to lock logs mutex")
            .push((level, target, message));
        Ok(())
    }
}

#[test]
fn test_callback_receives_logs_without_platform_logger() {
    let logs = Arc::new(Mutex::new(Vec::new()));
    let callback = Arc::new(TestCallback { logs: logs.clone() });

    init_logger(Some(callback), None, false);

    let _client = Client::new(
        Arc::new(MockTokenProvider),
        None,
        Arc::new(ManagedSettingsBindingClient::new()),
    );

    tracing::info!("platform logger disabled message");

    let captured = logs.lock().expect("Failed to lock logs mutex");
    let our_log = captured
        .iter()
        .find(|(_, _, msg)| msg.contains("platform logger disabled message"))
        .expect("Should find our test message");

    assert_eq!(our_log.0, LogLevel::Info);
}

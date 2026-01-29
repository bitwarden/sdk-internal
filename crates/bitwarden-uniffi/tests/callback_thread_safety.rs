//! Integration test validating callback thread safety.
//!
//! Verifies that the callback mechanism safely handles concurrent log emissions
//! from multiple SDK threads without data races or corruption.

use std::{
    sync::{Arc, Mutex},
    thread,
};

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

/// Thread-safe test callback
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
fn test_callback_thread_safety() {
    // Verify callback handles concurrent invocations safely
    let logs = Arc::new(Mutex::new(Vec::new()));
    let callback = Arc::new(TestCallback { logs: logs.clone() });

    // Initialize logger with callback
    init_logger(Some(callback));

    let _client = Client::new(Arc::new(MockTokenProvider), None);

    // Spawn multiple threads logging simultaneously
    let handles: Vec<_> = (0..10)
        .map(|i| {
            thread::spawn(move || {
                tracing::info!("thread {} message", i);
            })
        })
        .collect();

    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread should not panic");
    }

    // Verify all logs captured without data races (tests run in parallel so may have logs from other tests)
    let captured = logs.lock().expect("Failed to lock logs mutex");
    
    // Find our specific thread messages
    let our_logs: Vec<_> = captured
        .iter()
        .filter(|(lvl, _, msg)| lvl == "INFO" && msg.contains("thread") && msg.contains("message"))
        .collect();
    
    assert_eq!(our_logs.len(), 10, "All 10 threaded logs should be captured");

    // Verify no corrupted entries (all should be INFO level with thread messages)
    for (level, _target, message) in our_logs.iter() {
        assert_eq!(level, "INFO");
        assert!(message.contains("thread"));
        assert!(message.contains("message"));
    }
}

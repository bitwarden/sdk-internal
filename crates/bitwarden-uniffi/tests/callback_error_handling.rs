//! Integration test validating SDK resilience to callback errors.
//!
//! Verifies that the SDK continues operating normally when the registered callback
//! returns errors, preventing mobile callback failures from crashing the SDK.

use std::sync::Arc;

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

/// Failing callback that always returns errors
struct FailingCallback;

impl LogCallback for FailingCallback {
    fn on_log(&self, _level: String, _target: String, _message: String) -> Result<()> {
        // Simulate mobile callback exception
        // Use a simple error that will be converted at FFI boundary
        Err(bitwarden_uniffi::error::BitwardenError::Conversion(
            "Simulated mobile callback failure".to_string(),
        ))
    }
}

#[test]
fn test_callback_error_does_not_crash_sdk() {
    // Initialize logger with failing callback
    init_logger(Some(Arc::new(FailingCallback)));

    // Create client
    let client = Client::new(Arc::new(MockTokenProvider), None);

    // SDK should work before triggering callback
    assert_eq!(client.echo("test".into()), "test");

    // Trigger logs that invoke failing callback
    tracing::info!("This log triggers failing callback");
    tracing::warn!("Another log that fails");
    tracing::error!("Yet another failing log");

    // Verify SDK still operational after multiple callback errors
    assert_eq!(client.echo("still works".into()), "still works");

    // SDK operations continue normally despite callback failures
    assert_eq!(
        client.echo("definitely still working".into()),
        "definitely still working"
    );
}

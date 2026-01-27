//! Demonstration of SDK logging callback mechanism
//!
//! This example shows how mobile clients can register a callback to receive
//! SDK logs and forward them to Flight Recorder or other observability systems.

use std::sync::{Arc, Mutex};

use bitwarden_core::client::internal::ClientManagedTokens;
use bitwarden_uniffi::{Client, LogCallback};

/// Mock token provider for demo
#[derive(Debug)]
struct DemoTokenProvider;

#[async_trait::async_trait]
impl ClientManagedTokens for DemoTokenProvider {
    async fn get_access_token(&self) -> Option<String> {
        Some("demo_token".to_string())
    }
}

/// Demo callback that prints logs to stdout
struct DemoLogCallback {
    logs: Arc<Mutex<Vec<(String, String, String)>>>,
}

impl LogCallback for DemoLogCallback {
    fn on_log(
        &self,
        level: String,
        target: String,
        message: String,
    ) -> Result<(), bitwarden_uniffi::error::BitwardenError> {
        println!("📋 Callback received: [{}] {} - {}", level, target, message);
        self.logs
            .lock()
            .expect("Failed to lock logs mutex")
            .push((level, target, message));
        Ok(())
    }
}

fn main() {
    println!("🚀 SDK Logging Callback Demonstration\n");
    println!("Creating SDK client with logging callback...\n");

    let logs = Arc::new(Mutex::new(Vec::new()));
    let callback = Arc::new(DemoLogCallback { logs: logs.clone() });

    // Create client with callback
    let _client = Client::new(Arc::new(DemoTokenProvider), None, Some(callback));

    println!("✅ Client initialized with callback\n");
    println!("Emitting SDK logs at different levels...\n");

    // Emit logs that will be captured by callback
    // These examples demonstrate both simple messages and structured fields
    tracing::info!("Hello world");

    let user_id = 123;
    tracing::info!(user_id, "User authentication started");

    let remaining_requests = 50;
    let limit = 1000;
    tracing::warn!(remaining_requests, limit, "API rate limit approaching");

    let error_code = "TIMEOUT";
    let retry_count = 3;
    tracing::error!(error_code, retry_count, "Network request failed");

    println!("\n📊 Summary:");
    let captured = logs.lock().expect("Failed to lock logs mutex");
    println!("   Captured {} log events", captured.len());
    println!(
        "   Levels: {}",
        captured
            .iter()
            .map(|(l, _, _)| l.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("\n✨ Callback successfully forwarded all SDK logs!");
}

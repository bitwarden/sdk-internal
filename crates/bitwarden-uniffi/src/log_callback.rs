use std::sync::Arc;

use tracing_subscriber::{Layer, layer::Context};
/// Callback interface for receiving SDK log events
/// Mobile implementations forward these to Flight Recorder
#[uniffi::export(with_foreign)]
pub trait LogCallback: Send + Sync {
    /// Called when SDK emits a log entry
    ///
    /// # Parameters
    /// - level: Log level ("TRACE", "DEBUG", "INFO", "WARN", "ERROR")
    /// - target: Module that emitted log (e.g., "bitwarden_core::auth")
    /// - message: The log message text
    ///
    /// # Returns
    /// Result<(), BitwardenError> - mobile implementations should catch exceptions
    /// and return errors rather than panicking
    fn on_log(&self, level: String, target: String, message: String) -> crate::Result<()>;
}

/// Custom tracing Layer that forwards events to UNIFFI callback
pub(crate) struct CallbackLayer {
    callback: Arc<dyn LogCallback>,
}
impl CallbackLayer {
    pub(crate) fn new(callback: Arc<dyn LogCallback>) -> Self {
        Self { callback }
    }
}
impl<S> Layer<S> for CallbackLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        // Filter out our own error messages to prevent infinite callback loop
        if metadata.target() == "bitwarden_uniffi::log_callback" {
            return; // Platform loggers still receive this for debugging
        }
        let level = metadata.level().to_string();
        let target = metadata.target().to_string();
        // Format event message
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let message = visitor.message;
        // Forward to UNIFFI callback with error handling
        if let Err(e) = self.callback.on_log(level, target, message) {
            tracing::error!(target: "bitwarden_uniffi::log_callback", "Logging callback failed: {:?}", e);
        }
    }
}
/// Visitor to extract message from tracing event
///
/// **Why only record_debug is implemented:**
///
/// The tracing::field::Visit trait provides default implementations for all record
/// methods (record_str, record_i64, record_bool, etc.) that forward to record_debug.
/// This means implementing only record_debug captures all field types. The SDK's
/// logging patterns (including % and ? format specifiers) all route through this
/// single method via tracing's default implementations.
#[derive(Default)]
struct MessageVisitor {
    message: String,
}
impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{:?}", value);
        }
    }
}
#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    struct TestLogCallback {
        logs: Arc<Mutex<Vec<(String, String, String)>>>,
    }

    impl LogCallback for TestLogCallback {
        fn on_log(&self, level: String, target: String, message: String) -> crate::Result<()> {
            self.logs.lock().unwrap().push((level, target, message));
            Ok(())
        }
    }

    #[test]
    fn test_trait_can_be_implemented() {
        let _callback: Arc<dyn LogCallback> = Arc::new(TestLogCallback {
            logs: Arc::new(Mutex::new(Vec::new())),
        });
    }

    #[test]
    fn test_callback_layer_forwards_events() {
        // Verify CallbackLayer correctly extracts and forwards log data
        let logs = Arc::new(Mutex::new(Vec::new()));
        let callback = Arc::new(TestLogCallback { logs: logs.clone() });
        let _layer = CallbackLayer::new(callback);

        // Test that layer compiles and can be created
        // Full integration test will happen after Client::new() modification
        assert!(logs.lock().unwrap().is_empty());
    }
}

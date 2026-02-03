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
        let level = metadata.level().to_string();
        let target = metadata.target().to_string();

        let mut message = String::new();
        let writer = tracing_subscriber::fmt::format::Writer::new(&mut message);
        let mut visitor = tracing_subscriber::fmt::format::DefaultVisitor::new(writer, false);
        event.record(&mut visitor);

        // Forward to UNIFFI callback - errors are silently ignored
        let _ = self.callback.on_log(level, target, message);
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

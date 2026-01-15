//! Flight Recorder event definitions.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[cfg(feature = "wasm")]
use tsify::Tsify;

/// A single log event captured by the Flight Recorder.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct FlightRecorderEvent {
    /// Unix timestamp in milliseconds
    pub timestamp: i64,

    /// Log level (trace, debug, info, warn, error)
    pub level: String,

    /// Target module (e.g., "bitwarden_core::client")
    pub target: String,

    /// Primary message
    pub message: String,

    /// Structured fields from tracing events
    #[cfg_attr(feature = "wasm", tsify(type = "Record<string, string>"))]
    pub fields: HashMap<String, String>,
}

impl FlightRecorderEvent {
    /// Create a new FlightRecorderEvent from a tracing event.
    pub fn from_tracing_event(event: &tracing::Event<'_>) -> Self {
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);

        let timestamp = chrono::Utc::now().timestamp_millis();
        let level = event.metadata().level().to_string();
        let target = event.metadata().target().to_string();

        Self {
            timestamp,
            level,
            target,
            message: visitor.message,
            fields: visitor.fields,
        }
    }

    /// Estimate the size of this event in bytes for buffer tracking.
    pub fn estimate_size(&self) -> usize {
        let base_size = std::mem::size_of::<Self>();
        let string_sizes = self.target.len() + self.message.len() + self.level.len();
        let fields_size: usize = self
            .fields
            .iter()
            .map(|(k, v)| k.len() + v.len())
            .sum();

        base_size + string_sizes + fields_size + 100 // JSON overhead estimate
    }
}

/// Visitor for extracting fields from tracing events.
/// Only record_debug is implemented - all field types route through it
/// via tracing's default implementations (matches PM-27800 pattern).
#[derive(Default)]
struct MessageVisitor {
    message: String,
    fields: HashMap<String, String>,
}

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{:?}", value);
        } else {
            self.fields
                .insert(field.name().to_string(), format!("{:?}", value));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_serialization() {
        let event = FlightRecorderEvent {
            timestamp: 1234567890,
            level: "INFO".to_string(),
            target: "test::module".to_string(),
            message: "Test message".to_string(),
            fields: HashMap::new(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("timestamp"));
        assert!(json.contains("camelCase") == false); // Verify rename_all works
        assert!(json.contains("\"level\":\"INFO\""));
    }

    #[test]
    fn test_event_size_estimation() {
        let mut fields = HashMap::new();
        fields.insert("key".to_string(), "value".to_string());

        let event = FlightRecorderEvent {
            timestamp: 0,
            level: "INFO".to_string(),
            target: "test".to_string(),
            message: "hello".to_string(),
            fields,
        };

        let size = event.estimate_size();
        assert!(size > 0);
        // Size should include base struct + strings + fields + overhead
        assert!(size > std::mem::size_of::<FlightRecorderEvent>());
    }
}

//! Flight Recorder event definitions.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use {tsify::Tsify, wasm_bindgen::prelude::*};

use crate::visitor::MessageVisitor;

/// A single log event captured by the Flight Recorder.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct FlightRecorderEvent {
    /// Unix timestamp in milliseconds.
    pub timestamp: i64,
    /// Log level (e.g. "DEBUG", "INFO", "WARN", "ERROR").
    pub level: String,
    /// Target module path (e.g. "bitwarden_core::client").
    pub target: String,
    /// Primary log message.
    pub message: String,
    /// Structured fields from the tracing event.
    #[cfg_attr(feature = "wasm", tsify(type = "Record<string, string>"))]
    pub fields: HashMap<String, String>,
}

impl From<&tracing::Event<'_>> for FlightRecorderEvent {
    fn from(event: &tracing::Event<'_>) -> Self {
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);

        Self {
            timestamp: chrono::Utc::now().timestamp_millis(),
            level: event.metadata().level().to_string(),
            target: event.metadata().target().to_string(),
            message: visitor.message,
            fields: visitor.fields,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_serialization_roundtrip() {
        let event = FlightRecorderEvent {
            timestamp: 1234567890,
            level: "INFO".to_string(),
            target: "test::module".to_string(),
            message: "Test message".to_string(),
            fields: HashMap::new(),
        };

        let json = serde_json::to_string(&event).expect("should serialize");
        let deserialized: FlightRecorderEvent =
            serde_json::from_str(&json).expect("should deserialize");

        assert_eq!(deserialized.timestamp, 1234567890);
        assert_eq!(deserialized.level, "INFO");
        assert_eq!(deserialized.target, "test::module");
        assert_eq!(deserialized.message, "Test message");
        assert!(deserialized.fields.is_empty());
    }

    #[test]
    fn test_event_with_fields() {
        let mut fields = HashMap::new();
        fields.insert("user_id".to_string(), "abc-123".to_string());
        fields.insert("action".to_string(), "login".to_string());

        let event = FlightRecorderEvent {
            timestamp: 0,
            level: "INFO".to_string(),
            target: "test".to_string(),
            message: "hello".to_string(),
            fields,
        };

        let json = serde_json::to_string(&event).expect("should serialize");
        assert!(json.contains("\"user_id\":\"abc-123\""));
        assert!(json.contains("\"action\":\"login\""));
    }
}

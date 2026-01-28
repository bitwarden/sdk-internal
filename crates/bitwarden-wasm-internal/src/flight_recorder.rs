//! WASM bindings for Flight Recorder.

use bitwarden_flight_recorder::{drain_flight_recorder, flight_recorder_count};
use wasm_bindgen::prelude::*;

// TypeScript type definition for proper IDE support
#[wasm_bindgen(typescript_custom_section)]
const TS_APPEND_CONTENT: &'static str = r#"
export interface FlightRecorderClient {
    drain(): FlightRecorderEvent[];
    count(): number;
}
"#;

/// WASM client for Flight Recorder operations.
///
/// Note: This client does NOT wrap the main Client struct because
/// the Flight Recorder buffer is global (initialized in init_sdk),
/// not tied to a specific PasswordManagerClient instance.
#[wasm_bindgen]
pub struct FlightRecorderClient;

#[wasm_bindgen]
impl FlightRecorderClient {
    /// Create a new FlightRecorderClient.
    ///
    /// The buffer is global, so this is just a handle for WASM access.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self
    }

    /// Drain all events from the Flight Recorder buffer.
    ///
    /// Returns events as JsValue (serialized via serde_wasm_bindgen).
    /// After calling this, the buffer is empty.
    ///
    /// Note: We return JsValue and use serde_wasm_bindgen for serialization
    /// because Vec<CustomType> requires explicit conversion across WASM boundary.
    /// The TypeScript type is defined via typescript_custom_section above.
    pub fn drain(&self) -> JsValue {
        let events = drain_flight_recorder();
        tsify::serde_wasm_bindgen::to_value(&events).unwrap_or(JsValue::UNDEFINED)
    }

    /// Get current event count without draining.
    pub fn count(&self) -> usize {
        flight_recorder_count()
    }
}

impl Default for FlightRecorderClient {
    fn default() -> Self {
        Self::new()
    }
}

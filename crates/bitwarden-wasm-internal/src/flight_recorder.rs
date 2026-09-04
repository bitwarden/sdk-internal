//! WASM bindings for the Flight Recorder.

use bitwarden_logging::{
    FlightRecorderEvent, flight_recorder_count, read_flight_recorder, write_flight_recorder,
};
use wasm_bindgen::prelude::*;

use crate::init::{LogLevel, convert_level};

/// WASM client for reading Flight Recorder logs.
///
/// The underlying buffer is global (initialized in [`init_sdk`](crate::init_sdk)),
/// so this client is a stateless handle for WASM access.
#[bitwarden_ffi::wasm_object]
pub struct FlightRecorderClient;

#[bitwarden_ffi::wasm_export]
impl FlightRecorderClient {
    /// Create a new `FlightRecorderClient`.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self
    }

    /// Read all events currently in the Flight Recorder buffer.
    pub fn read(&self) -> Vec<FlightRecorderEvent> {
        read_flight_recorder()
    }

    /// Get the current event count without reading event contents.
    pub fn count(&self) -> usize {
        flight_recorder_count()
    }

    /// Ingest a single TypeScript-originated log event into the global buffer,
    /// honoring the configured level floor.
    ///
    /// `timestamp` is milliseconds since the Unix epoch, supplied by the caller
    /// (`Date.now()`).
    pub fn write(&self, timestamp: f64, level: LogLevel, target: String, message: String) {
        let level = convert_level(level);
        let event = FlightRecorderEvent {
            timestamp: timestamp as i64,
            level: level.to_string(),
            target,
            message,
            fields: Default::default(),
        };
        write_flight_recorder(event, level);
    }
}

impl Default for FlightRecorderClient {
    fn default() -> Self {
        Self::new()
    }
}

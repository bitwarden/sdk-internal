//! WASM bindings for the Flight Recorder.

use bitwarden_logging::{FlightRecorderEvent, flight_recorder_count, read_flight_recorder};
use wasm_bindgen::prelude::*;

/// WASM client for reading Flight Recorder logs.
///
/// The underlying buffer is global (initialized in [`init_sdk`](crate::init_sdk)),
/// so this client is a stateless handle for WASM access.
#[wasm_bindgen]
pub struct FlightRecorderClient;

#[wasm_bindgen]
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
}

impl Default for FlightRecorderClient {
    fn default() -> Self {
        Self::new()
    }
}

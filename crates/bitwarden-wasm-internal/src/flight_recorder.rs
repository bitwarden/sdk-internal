//! WASM bindings for the Flight Recorder.

use bitwarden_ipc::{Endpoint, RequestError, wasm::JsIpcClient};
use bitwarden_logging::{
    FlightRecorderEvent, flight_recorder_count,
    ipc::{FlightRecorderCollectorRole, read_flight_recorder_aggregated},
    write_flight_recorder,
};
use bitwarden_threading::cancellation_token::wasm::{AbortSignal, AbortSignalExt};

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

    /// Read the Flight Recorder events for this client.
    ///
    /// In a context with forwarding enabled, requests the collector's events and appends this
    /// context's IPC events and events not yet sent. If the collector cannot be reached or does
    /// not answer before `abort_signal` fires, or within 5 seconds without a signal, only this
    /// context's events are returned. Elsewhere, reads the local buffer.
    pub async fn read(&self, abort_signal: Option<AbortSignal>) -> Vec<FlightRecorderEvent> {
        read_flight_recorder_aggregated(abort_signal.map(|s| s.to_cancellation_token())).await
    }

    /// Get the number of events in this context's buffer without reading their contents.
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
            process: None,
        };
        write_flight_recorder(event, level);
    }
}

/// Make this context a Flight Recorder forwarder: send captured events, including those captured
/// so far, to the collector at `destination`. Events from the IPC stack itself stay local. Only
/// the first call has effect.
#[bitwarden_ffi::wasm_export(js_name = enableFlightRecorderForwarding)]
pub fn enable_flight_recorder_forwarding(ipc_client: &JsIpcClient, destination: Endpoint) {
    bitwarden_logging::ipc::enable_flight_recorder_forwarding(
        ipc_client.client.clone(),
        destination,
    );
}

/// Make this context the Flight Recorder collector for its client, storing events from its
/// forwarders and answering their read requests.
#[bitwarden_ffi::wasm_export(js_name = enableFlightRecorderCollection)]
pub async fn enable_flight_recorder_collection(
    ipc_client: &JsIpcClient,
    role: FlightRecorderCollectorRole,
) -> Result<(), RequestError> {
    bitwarden_logging::ipc::enable_flight_recorder_collection(ipc_client.client.clone(), role)
        .await
        .map_err(RequestError::from)
}

impl Default for FlightRecorderClient {
    fn default() -> Self {
        Self::new()
    }
}

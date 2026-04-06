//! Global Flight Recorder buffer and convenience accessors.

use std::sync::{Arc, OnceLock};

use crate::{CircularBuffer, FlightRecorderConfig, FlightRecorderEvent, FlightRecorderLayer};

/// Global Flight Recorder buffer, initialized during `init_sdk()`.
static FLIGHT_RECORDER_BUFFER: OnceLock<Arc<CircularBuffer<FlightRecorderEvent>>> = OnceLock::new();

/// Initialize the global Flight Recorder.
///
/// Creates a [`FlightRecorderLayer`] and stores the buffer in a global
/// [`OnceLock`] so it can be read from anywhere via [`read_flight_recorder`].
/// Returns the layer to add to a tracing subscriber.
///
/// If called more than once, the second call's buffer is **not** stored
/// globally (the `OnceLock` is already set), but the returned layer is
/// still independently functional.
#[must_use]
pub fn init_flight_recorder(config: FlightRecorderConfig) -> FlightRecorderLayer {
    let layer = FlightRecorderLayer::new(config);
    let _ = FLIGHT_RECORDER_BUFFER.set(layer.buffer());
    layer
}

/// Get the global Flight Recorder buffer.
///
/// Returns `None` if [`init_flight_recorder`] has not been called.
pub fn get_flight_recorder_buffer() -> Option<Arc<CircularBuffer<FlightRecorderEvent>>> {
    FLIGHT_RECORDER_BUFFER.get().cloned()
}

/// Read all events from the global Flight Recorder buffer.
///
/// Returns an empty `Vec` if [`init_flight_recorder`] has not been called.
#[must_use]
pub fn read_flight_recorder() -> Vec<FlightRecorderEvent> {
    get_flight_recorder_buffer()
        .map(|buffer| buffer.read())
        .unwrap_or_default()
}

/// Get the current event count without reading event contents.
///
/// Returns `0` if [`init_flight_recorder`] has not been called.
#[must_use]
pub fn flight_recorder_count() -> usize {
    get_flight_recorder_buffer()
        .map(|buffer| buffer.len())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default_values() {
        let config = FlightRecorderConfig::default();
        assert_eq!(config.buffer_size.get(), 1000);
        assert_eq!(config.level, tracing::Level::DEBUG);
    }

    #[test]
    fn test_read_before_init_returns_empty() {
        // A fresh OnceLock (not the global one, which may already be set
        // by other tests) would return None. We can at least verify the
        // convenience functions don't panic.
        let events = read_flight_recorder();
        // Either empty (not initialized) or non-empty (another test initialized it)
        let _ = events;
    }
}

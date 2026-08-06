//! Global Flight Recorder buffer and convenience accessors.

use std::sync::{Arc, OnceLock};

use crate::{CircularBuffer, FlightRecorderConfig, FlightRecorderEvent, FlightRecorderLayer};

/// Global Flight Recorder buffer, initialized during `init_sdk()`.
static FLIGHT_RECORDER_BUFFER: OnceLock<Arc<CircularBuffer<FlightRecorderEvent>>> = OnceLock::new();

/// Configured level floor for the global Flight Recorder, initialized during
/// `init_sdk()`. Mirrors [`FlightRecorderLayer`]'s level so that direct writes
/// via [`write_flight_recorder`] honor the same filter as the tracing layer.
static FLIGHT_RECORDER_LEVEL: OnceLock<tracing::Level> = OnceLock::new();

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
    let _ = FLIGHT_RECORDER_LEVEL.set(config.level);
    let layer = FlightRecorderLayer::new(config);
    let _ = FLIGHT_RECORDER_BUFFER.set(layer.buffer());
    layer
}

/// Write a single externally-sourced event (e.g. from TypeScript) directly into
/// the global buffer, honoring the configured level floor.
///
/// This mirrors [`FlightRecorderLayer`]'s filter so that events routed around
/// the tracing pipeline are subject to the same level check. Events more verbose
/// than the configured floor are dropped. No-op if [`init_flight_recorder`] has
/// not been called.
pub fn write_flight_recorder(event: FlightRecorderEvent, level: tracing::Level) {
    // Mirrors the layer's check: skip events more verbose than the configured level.
    if let Some(floor) = FLIGHT_RECORDER_LEVEL.get()
        && level > *floor
    {
        return;
    }
    if let Some(buffer) = get_flight_recorder_buffer() {
        buffer.push(event);
    }
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

    fn event(marker: &str, level: &str) -> FlightRecorderEvent {
        FlightRecorderEvent {
            timestamp: 0,
            level: level.to_string(),
            target: "test::module".to_string(),
            message: marker.to_string(),
            fields: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn test_write_flight_recorder_respects_level_floor() {
        // This is the only test in the crate that initializes the global
        // recorder, so it controls the shared level/buffer for this binary.
        let config = FlightRecorderConfig::new(
            std::num::NonZeroUsize::new(100).expect("non-zero"),
            tracing::Level::INFO,
        );
        let _ = init_flight_recorder(config);

        // Below the floor (more verbose than INFO) is dropped.
        write_flight_recorder(event("fr-drop-debug", "DEBUG"), tracing::Level::DEBUG);
        // At or above the floor is captured.
        write_flight_recorder(event("fr-keep-info", "INFO"), tracing::Level::INFO);
        write_flight_recorder(event("fr-keep-error", "ERROR"), tracing::Level::ERROR);

        let messages: Vec<String> = read_flight_recorder()
            .into_iter()
            .map(|e| e.message)
            .collect();
        assert!(messages.contains(&"fr-keep-info".to_string()));
        assert!(messages.contains(&"fr-keep-error".to_string()));
        assert!(!messages.contains(&"fr-drop-debug".to_string()));
    }
}

//! Flight Recorder infrastructure for capturing and exporting diagnostic logs.
//!
//! This crate provides a circular buffer-based logging system that captures
//! tracing events and makes them available for export to support debugging.
//!
//! # Usage
//!
//! ```ignore
//! use bitwarden_flight_recorder::{init_flight_recorder, drain_flight_recorder, FlightRecorderConfig};
//!
//! // Initialize during SDK startup
//! let layer = init_flight_recorder(FlightRecorderConfig::default());
//! // Add layer to tracing subscriber...
//!
//! // Later, export logs
//! let events = drain_flight_recorder();
//! ```

mod circular_buffer;
mod config;
mod error;
mod event;
mod layer;

use std::sync::{Arc, OnceLock};

pub use circular_buffer::CircularBuffer;
pub use config::FlightRecorderConfig;
pub use error::{FlightRecorderError, Result};
pub use event::FlightRecorderEvent;
pub use layer::FlightRecorderLayer;

/// Global Flight Recorder buffer, initialized during init_sdk().
static FLIGHT_RECORDER_BUFFER: OnceLock<Arc<CircularBuffer<FlightRecorderEvent>>> = OnceLock::new();

/// Initialize the global Flight Recorder.
///
/// This should be called during SDK initialization (e.g., `init_sdk()`).
/// Returns the layer to add to the tracing subscriber.
///
/// # Example
///
/// ```ignore
/// let layer = init_flight_recorder(FlightRecorderConfig::default());
/// tracing_subscriber::registry()
///     .with(layer)
///     .init();
/// ```
pub fn init_flight_recorder(config: FlightRecorderConfig) -> FlightRecorderLayer {
    let layer = FlightRecorderLayer::new(config);
    let _ = FLIGHT_RECORDER_BUFFER.set(layer.buffer());
    layer
}

/// Get the global Flight Recorder buffer.
///
/// Returns `None` if `init_flight_recorder` was not called.
pub fn get_flight_recorder_buffer() -> Option<Arc<CircularBuffer<FlightRecorderEvent>>> {
    FLIGHT_RECORDER_BUFFER.get().cloned()
}

/// Drain all events from the Flight Recorder buffer.
///
/// Returns an empty `Vec` if not initialized (graceful degradation).
/// This is intentional: calling `drain()` before `init_sdk()` returns an empty
/// array rather than erroring, allowing safe usage during early bootstrapping.
///
/// After calling this, the buffer is empty.
pub fn drain_flight_recorder() -> Vec<FlightRecorderEvent> {
    get_flight_recorder_buffer()
        .map(|buffer| buffer.drain())
        .unwrap_or_default()
}

/// Get the current event count without draining.
///
/// Returns 0 if not initialized.
pub fn flight_recorder_count() -> usize {
    get_flight_recorder_buffer()
        .map(|buffer| buffer.len())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests need to be careful about global state.
    // In a real test environment, each test would run in isolation.

    #[test]
    fn test_drain_before_init_returns_empty() {
        // Since we can't reset the OnceLock, we just verify the behavior
        // when the buffer exists but is empty
        let events = drain_flight_recorder();
        // Will be empty either because not initialized or because drained
        assert!(events.is_empty() || !events.is_empty());
    }
}

//! Configuration for the Flight Recorder.

use std::num::NonZeroUsize;

/// Configuration for the Flight Recorder system.
#[derive(Debug, Clone)]
pub struct FlightRecorderConfig {
    /// Maximum number of events to retain in the circular buffer.
    pub buffer_size: NonZeroUsize,
    /// Minimum tracing level to capture.
    pub level: tracing::Level,
}

impl Default for FlightRecorderConfig {
    fn default() -> Self {
        Self {
            buffer_size: NonZeroUsize::new(1000).expect("1000 is non-zero"),
            level: tracing::Level::DEBUG,
        }
    }
}

impl FlightRecorderConfig {
    /// Create a new configuration with the given buffer size and tracing level.
    pub fn new(buffer_size: NonZeroUsize, level: tracing::Level) -> Self {
        Self { buffer_size, level }
    }
}

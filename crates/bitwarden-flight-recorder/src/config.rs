//! Configuration types for Flight Recorder.

/// Configuration for the Flight Recorder system.
#[derive(Debug, Clone)]
pub struct FlightRecorderConfig {
    /// Maximum number of events in circular buffer
    pub max_events: usize,

    /// Maximum total size of buffer in bytes
    pub max_size_bytes: usize,
}

impl Default for FlightRecorderConfig {
    fn default() -> Self {
        Self {
            max_events: 1000,
            max_size_bytes: 5 * 1024 * 1024, // 5MB
        }
    }
}

impl FlightRecorderConfig {
    /// Set the maximum number of events to retain in the buffer.
    pub fn with_max_events(mut self, max: usize) -> Self {
        self.max_events = max;
        self
    }

    /// Set the maximum total size of the buffer in bytes.
    pub fn with_max_size_bytes(mut self, bytes: usize) -> Self {
        self.max_size_bytes = bytes;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = FlightRecorderConfig::default();
        assert_eq!(config.max_events, 1000);
        assert_eq!(config.max_size_bytes, 5 * 1024 * 1024);
    }

    #[test]
    fn test_config_builder() {
        let config = FlightRecorderConfig::default()
            .with_max_events(500)
            .with_max_size_bytes(1024);
        assert_eq!(config.max_events, 500);
        assert_eq!(config.max_size_bytes, 1024);
    }
}

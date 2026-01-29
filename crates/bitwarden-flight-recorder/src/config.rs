//! Configuration types for Flight Recorder.

/// Configuration for the Flight Recorder system.
#[derive(Debug, Clone)]
pub struct FlightRecorderConfig {
    /// Maximum number of events in circular buffer
    pub max_events: usize,
}

impl Default for FlightRecorderConfig {
    fn default() -> Self {
        Self { max_events: 1000 }
    }
}

impl FlightRecorderConfig {
    /// Set the maximum number of events to retain in the buffer.
    #[must_use]
    pub fn with_max_events(mut self, max: usize) -> Self {
        self.max_events = max;
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
    }

    #[test]
    fn test_config_builder() {
        let config = FlightRecorderConfig::default().with_max_events(500);
        assert_eq!(config.max_events, 500);
    }
}

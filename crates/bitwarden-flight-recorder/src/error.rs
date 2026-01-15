//! Error types for Flight Recorder operations.

/// Placeholder for FlightRecorderError - implementation in FR-002
#[derive(Debug)]
pub enum FlightRecorderError {}

/// Result type for Flight Recorder operations
pub type Result<T> = std::result::Result<T, FlightRecorderError>;

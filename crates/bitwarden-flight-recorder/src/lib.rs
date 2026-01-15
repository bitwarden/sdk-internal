//! Flight Recorder infrastructure for capturing and exporting diagnostic logs.
//!
//! This crate provides a circular buffer-based logging system that captures
//! tracing events and makes them available for export to support debugging.

mod circular_buffer;
mod config;
mod error;
mod event;
mod layer;

pub use circular_buffer::CircularBuffer;
pub use config::FlightRecorderConfig;
pub use error::{FlightRecorderError, Result};
pub use event::FlightRecorderEvent;
pub use layer::FlightRecorderLayer;

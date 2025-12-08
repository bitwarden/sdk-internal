use tracing::Level;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub enum TracingLevel {
    /// The "trace" level.
    ///
    /// Designates very low priority, often extremely verbose, information.
    Trace,
    /// The "debug" level.
    ///
    /// Designates lower priority information.
    Debug,
    /// The "info" level.
    ///
    /// Designates useful information.
    Info,
    /// The "warn" level.
    ///
    /// Designates hazardous situations.
    Warn,
    /// The "error" level.
    ///
    /// Designates very serious errors.
    Error,
}

impl From<TracingLevel> for Level {
    fn from(level: TracingLevel) -> Self {
        match level {
            TracingLevel::Trace => Level::TRACE,
            TracingLevel::Debug => Level::DEBUG,
            TracingLevel::Info => Level::INFO,
            TracingLevel::Warn => Level::WARN,
            TracingLevel::Error => Level::ERROR,
        }
    }
}

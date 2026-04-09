use std::num::NonZeroUsize;

use bitwarden_logging::{FlightRecorderConfig, init_flight_recorder};
use tracing::Level;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt as _, util::SubscriberInitExt as _};
use tracing_web::MakeWebConsoleWriter;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

fn convert_level(level: LogLevel) -> Level {
    match level {
        LogLevel::Trace => Level::TRACE,
        LogLevel::Debug => Level::DEBUG,
        LogLevel::Info => Level::INFO,
        LogLevel::Warn => Level::WARN,
        LogLevel::Error => Level::ERROR,
    }
}

/// Initialize the SDK. Must be called before using any other API.
/// Only the first invocation has effect; subsequent calls are ignored.
///
/// - `log_level`: Minimum level for console output. Defaults to `Info`.
/// - `flight_recorder_level`: Minimum level for the flight recorder. Defaults to `Info`.
/// - `flight_recorder_buffer_size`: Ring-buffer capacity for the flight recorder. Defaults to 1000.
///   Pass `0` to disable the flight recorder entirely.
#[wasm_bindgen]
pub fn init_sdk(
    log_level: Option<LogLevel>,
    flight_recorder_level: Option<LogLevel>,
    flight_recorder_buffer_size: Option<usize>,
) {
    console_error_panic_hook::set_once();

    let log_level = convert_level(log_level.unwrap_or(LogLevel::Info));
    let flight_recorder_level = convert_level(flight_recorder_level.unwrap_or(LogLevel::Info));
    let flight_recorder_buffer_size =
        NonZeroUsize::new(flight_recorder_buffer_size.unwrap_or(1000));

    // If the flight recorder buffer size we get is zero, we disable the flight recorder entirely.
    let flight_recorder_layer = flight_recorder_buffer_size.map(|size| {
        let config = FlightRecorderConfig::new(size, flight_recorder_level);
        init_flight_recorder(config)
    });

    let fmt = tracing_subscriber::fmt::layer()
        .with_ansi(false) // only partially supported across browsers
        .without_time() // time is not supported in wasm
        .with_writer(MakeWebConsoleWriter::new()); // write events to the console

    let filter = EnvFilter::builder()
        .with_default_directive(log_level.into())
        .from_env_lossy();

    let perf_layer = cfg!(feature = "performance-tracing").then(|| {
        tracing_web::performance_layer()
            .with_details_from_fields(tracing_subscriber::fmt::format::Pretty::default())
    });

    let _ = tracing_subscriber::registry()
        .with(flight_recorder_layer)
        .with(fmt)
        .with(filter)
        .with(perf_layer)
        .try_init();

    #[cfg(feature = "dangerous-crypto-debug")]
    tracing::warn!(
        "Dangerous crypto debug features are enabled. THIS MUST NOT BE USED IN PRODUCTION BUILDS!!"
    );
}

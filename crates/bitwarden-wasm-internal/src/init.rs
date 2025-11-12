use log::{Level, set_max_level};
use tracing_subscriber::{layer::SubscriberExt, prelude::*};
use tracing_web::MakeWebConsoleWriter;
use wasm_bindgen::prelude::*;

use wasm_bindgen_futures::js_sys;

use crate::flight_recorder_callback_writer::FlightRecorderCallbackWriter;

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
        LogLevel::Trace => Level::Trace,
        LogLevel::Debug => Level::Debug,
        LogLevel::Info => Level::Info,
        LogLevel::Warn => Level::Warn,
        LogLevel::Error => Level::Error,
    }
}

#[wasm_bindgen]
pub fn set_log_level(level: LogLevel) {
    let log_level = convert_level(level);
    set_max_level(log_level.to_level_filter());
}

#[allow(missing_docs)]
#[wasm_bindgen]
pub fn init_sdk(log_level: Option<LogLevel>, log_callback: Option<js_sys::Function>) {
    console_error_panic_hook::set_once();

    // Always use console writer for main logging
    let console_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false) // Only partially supported across browsers
        .without_time() // Time is not supported in wasm
        .with_writer(MakeWebConsoleWriter::new());

    if let Some(callback) = log_callback {
        let callback_layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .without_time()
            .with_writer(FlightRecorderCallbackWriter::new(callback));

        tracing_subscriber::registry().with(callback_layer).init();
        tracing::info!("Initialized tracing with flight recorder");
    } else {
        tracing_subscriber::registry().with(console_layer).init();
        tracing::info!("Initialized tracing");
    }

    let log_level = convert_level(log_level.unwrap_or(LogLevel::Info));
    if let Err(_e) = console_log::init_with_level(log_level) {
        set_max_level(log_level.to_level_filter())
    }
}

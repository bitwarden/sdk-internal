use tracing::Level;
use tracing_subscriber::{
    EnvFilter,
    fmt::{format::Pretty, time::UtcTime},
    layer::SubscriberExt as _,
    util::SubscriberInitExt as _,
};
use tracing_web::{MakeWebConsoleWriter, performance_layer};
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

#[allow(missing_docs)]
#[wasm_bindgen]
pub fn init_sdk(log_level: Option<LogLevel>) {
    console_error_panic_hook::set_once();

    let log_level = convert_level(log_level.unwrap_or(LogLevel::Info));

    let filter = EnvFilter::builder()
        .with_default_directive(log_level.into())
        .from_env_lossy();

    let fmt = tracing_subscriber::fmt::layer()
        .with_ansi(false) // only partially supported across browsers
        .without_time() // time is not supported in wasm
        .with_writer(MakeWebConsoleWriter::new()); // write events to the console

    let perf_layer = performance_layer().with_details_from_fields(Pretty::default());

    tracing_subscriber::registry()
        .with(perf_layer)
        .with(filter)
        .with(fmt)
        .init();
}

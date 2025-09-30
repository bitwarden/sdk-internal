use log::{Level, set_max_level};
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
pub fn init_sdk(log_level: Option<LogLevel>) {
    console_error_panic_hook::set_once();
    let log_level = convert_level(log_level.unwrap_or(LogLevel::Info));
    if let Err(_e) = console_log::init_with_level(log_level) {
        set_max_level(log_level.to_level_filter())
    }
}

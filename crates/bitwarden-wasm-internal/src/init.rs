use log::{set_max_level, Level};
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

// This is needed to ensure the linker doesn't optimize away the constructors used by the inventory
// crate. https://docs.rs/inventory/0.3.20/inventory/index.html#webassembly-and-constructors
unsafe extern "C" {
    fn __wasm_call_ctors();
}

#[wasm_bindgen(start)]
fn start() {
    unsafe {
        __wasm_call_ctors();
    }
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

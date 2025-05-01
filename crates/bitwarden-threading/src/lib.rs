mod function_bridge;
mod traits;

// Re-export types to make sure wasm_bindgen picks them up
#[cfg(feature = "wasm")]
pub mod wasm;

pub use function_bridge::{function_bridge, CallError, FunctionBridge};

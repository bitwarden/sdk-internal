mod call_bridge;
mod traits;

// Re-export types to make sure wasm_bindgen picks them up
#[cfg(feature = "wasm")]
pub mod wasm;

pub use call_bridge::{call_bridge, CallBridge, CallError};

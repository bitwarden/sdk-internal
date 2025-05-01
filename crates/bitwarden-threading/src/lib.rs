mod traits;

// Re-export types to make sure wasm_bindgen picks them up
#[cfg(feature = "wasm")]
pub mod wasm;

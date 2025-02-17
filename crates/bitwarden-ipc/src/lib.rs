mod endpoint;
mod error;
pub mod ipc_client;
mod manager;
mod message;
mod traits;

// Re-export types to make sure wasm_bindgen picks them up
#[cfg(feature = "wasm")]
pub mod wasm;

pub use manager::Manager;

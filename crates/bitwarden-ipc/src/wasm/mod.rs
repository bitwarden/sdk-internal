mod communication_backend;
mod error;
mod ipc_client;
mod message;

// Re-export types to make sure wasm_bindgen picks them up
pub use communication_backend::*;
pub use error::*;
pub use ipc_client::*;

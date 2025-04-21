mod endpoint;
mod error;
mod ipc_client;
mod message;
mod traits;

// Re-export types to make sure wasm_bindgen picks them up
#[cfg(feature = "wasm")]
pub mod wasm;

pub use ipc_client::IpcClient;

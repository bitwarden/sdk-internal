#![doc = include_str!("../README.md")]

mod client;
mod custom_types;
mod flight_recorder;
mod init;
mod platform;
mod pure_crypto;
mod ssh;

pub use bitwarden_ipc::wasm::*;
pub use bitwarden_server_communication_config::wasm::*;
// In order to fix an unused dependency error
#[cfg(not(target_arch = "wasm32"))]
pub use bitwarden_shared_unlock;
#[cfg(target_arch = "wasm32")]
pub use bitwarden_shared_unlock::wasm::*;
pub use client::PasswordManagerClient;
pub use flight_recorder::FlightRecorderClient;
pub use init::init_sdk;

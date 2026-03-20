#![allow(missing_docs)]

/// Re-export types to make sure wasm_bindgen picks them up
#[cfg(feature = "wasm")]
pub mod wasm;

mod backend;
mod client_manager;
mod sdk_managed;

pub use backend::{ClientHasNoUserIdError, ClientManagerBackend};
pub use client_manager::ClientManager;
pub use sdk_managed::SdkManagedBackend;

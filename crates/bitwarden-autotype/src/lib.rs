//! # Bitwarden Autotype
//!
//! Autotype support built on the SDK's encrypted IPC ([`bitwarden_ipc`]).
//!
//! The desktop client's autotype feature currently passes data between the Electron main process
//! and the renderer over plain Electron IPC channels, including decrypted vault data. This crate
//! hosts the request/response pairs that let that traffic move onto the SDK's Noise-encrypted IPC
//! transport instead.
//!
//! Today that is a single pair, [`echo`], which round-trips a message so the channel itself can be
//! verified end to end. Real autotype requests follow the same shape: define an
//! [`RpcRequest`](bitwarden_ipc::RpcRequest) with its response type, implement an
//! [`RpcHandler`](bitwarden_ipc::RpcHandler) for the responding side, and add thin
//! `#[wasm_bindgen]` wrappers in [`wasm`] so the clients can reach them.

pub mod echo;

/// Wasm support module for autotype.
#[cfg(feature = "wasm")]
pub mod wasm;

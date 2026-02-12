#![doc = include_str!("../README.md")]

mod constants;
mod crypto_provider;
mod discover;
mod endpoint;
mod ipc_client;
mod message;
mod rpc;
mod serde_utils;
mod traits;

/// Re-export types to make sure wasm_bindgen picks them up
#[cfg(feature = "wasm")]
pub mod wasm;

pub use ipc_client::{
    IpcClient, IpcClientSubscription, IpcClientTypedSubscription, ReceiveError, RequestError,
    SubscribeError, TypedReceiveError,
};
pub use rpc::exec::handler::RpcHandler;

#![doc = include_str!("../README.md")]

mod constants;
pub mod discover;
mod endpoint;
mod error;
mod ipc_client;
mod ipc_client_ext;
mod ipc_client_trait;
mod message;
mod presets;
mod rpc;
mod serde_utils;
mod traits;

/// Re-export types to make sure wasm_bindgen picks them up
#[cfg(feature = "wasm")]
pub mod wasm;

pub use endpoint::{Endpoint, HostId, Source};
pub use error::{ReceiveError, RequestError, SendError, SubscribeError, TypedReceiveError};
pub use ipc_client::{IpcClientImpl, IpcClientSubscription, IpcClientTypedSubscription};
pub use ipc_client_ext::IpcClientExt;
pub use ipc_client_trait::IpcClient;
pub use message::{IncomingMessage, OutgoingMessage};
pub use rpc::exec::handler::RpcHandler;
#[doc(hidden)]
pub use rpc::exec::handler::ErasedRpcHandler;
pub use traits::NoopCommunicationBackend;
#[cfg(any(test, feature = "test-support"))]
pub use traits::TestCommunicationBackend;

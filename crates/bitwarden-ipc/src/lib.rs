#![doc = include_str!("../README.md")]

mod constants;
mod crypto_provider;
pub mod discover;
mod endpoint;
mod error;
mod ipc_client;
mod ipc_client_ext;
mod ipc_client_trait;
mod message;
mod rpc;
mod serde_utils;
mod traits;

/// Re-export types to make sure wasm_bindgen picks them up
#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(any(test, feature = "test-support"))]
pub use crypto_provider::noise::crypto_provider::{NoiseCryptoProvider, NoiseCryptoProviderState};
pub use endpoint::{Endpoint, HostId, Source};
pub use error::{
    ErrorKind, IpcErrorKind, ReceiveError, RequestError, SendError, SubscribeError,
    TypedReceiveError,
};
pub use ipc_client::{IpcClientImpl, IpcClientSubscription, IpcClientTypedSubscription};
pub use ipc_client_ext::IpcClientExt;
pub use ipc_client_trait::IpcClient;
pub use message::{
    IncomingMessage, OutgoingMessage, PayloadTypeName, TypedIncomingMessage, TypedOutgoingMessage,
};
#[doc(hidden)]
pub use rpc::exec::handler::ErasedRpcHandler;
pub use rpc::{exec::handler::RpcHandler, request::RpcRequest};
#[cfg(any(test, feature = "test-support"))]
pub use traits::TestCommunicationBackend;
#[cfg(any(test, feature = "test-support"))]
pub use traits::{
    CommunicationBackend, CommunicationBackendReceiver, NoEncryptionCryptoProvider,
    SessionRepository,
};
pub use traits::{InMemorySessionRepository, NoopCommunicationBackend};

// Test configuration of the IPC client, always available in test and test-support contexts.
#[cfg(any(test, feature = "test-support"))]
#[allow(missing_docs)]
pub type TestIpcClient = ipc_client::IpcClientImpl<
    crate::traits::NoEncryptionCryptoProvider,
    crate::traits::TestCommunicationBackend,
    crate::traits::InMemorySessionRepository<()>,
>;

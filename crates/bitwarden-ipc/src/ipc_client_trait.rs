use bitwarden_threading::cancellation_token::CancellationToken;

use crate::{
    error::{AlreadyRunningError, SendError, SubscribeError},
    ipc_client::IpcClientSubscription,
    message::OutgoingMessage,
    rpc::exec::handler::ErasedRpcHandler,
};

/// Dyn-compatible trait for IPC client operations.
///
/// This trait provides the core IPC operations that consumers can use without
/// being tied to a specific concrete `IpcClient` implementation. For generic
/// convenience methods (typed subscriptions, RPC requests), use the
/// [`IpcClientExt`](crate::IpcClientExt) extension trait which is automatically
/// implemented for all `IpcClient` implementors.
#[async_trait::async_trait]
pub trait IpcClient: Send + Sync {
    /// Start the IPC client, which will begin listening for incoming messages and processing them.
    async fn start(
        &self,
        cancellation_token: Option<CancellationToken>,
    ) -> Result<(), AlreadyRunningError>;

    /// Check if the IPC client task is currently running.
    fn is_running(&self) -> bool;

    /// Send a message over IPC.
    ///
    /// Returning an error means this particular send failed. The client only stops processing
    /// messages when the underlying error is fatal (see
    /// [`IpcErrorKind`](crate::IpcErrorKind)); recoverable errors leave the client running, so the
    /// send can be retried and existing subscriptions remain valid.
    ///
    /// Payloads are limited to 5 MiB. Payloads larger than one crypto provider message are split
    /// into separately encrypted fragments that the receiving client reassembles. A peer that
    /// predates fragmentation receives the fragments as messages on an unknown topic. Topics
    /// `IpcFragment` and `IpcFragment/<topic>` are reserved for fragments, and sending on them
    /// returns an error.
    async fn send(&self, message: OutgoingMessage) -> Result<(), SendError>;

    /// Subscribe to receive messages, optionally filtered by topic.
    /// Setting the topic to `None` will receive all messages.
    async fn subscribe(
        &self,
        topic: Option<String>,
    ) -> Result<IpcClientSubscription, SubscribeError>;

    /// Register an RPC handler using its type-erased form.
    /// Prefer using
    /// [`IpcClientExt::register_rpc_handler`](crate::IpcClientExt::register_rpc_handler)
    /// instead.
    #[doc(hidden)]
    async fn register_rpc_handler_erased(&self, name: &str, handler: Box<dyn ErasedRpcHandler>);
}

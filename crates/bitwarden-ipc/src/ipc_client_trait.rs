use bitwarden_threading::cancellation_token::CancellationToken;

use crate::{
    endpoint::Endpoint,
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

    /// Whether `destination` is reachable.
    async fn is_reachable(&self, destination: Endpoint) -> bool;

    /// Immediately mark `endpoint` as unreachable (e.g. on a transport disconnect)
    fn invalidate_reachability(&self, endpoint: Endpoint);
}

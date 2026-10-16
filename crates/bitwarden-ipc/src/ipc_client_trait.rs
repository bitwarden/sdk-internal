use bitwarden_threading::cancellation_token::CancellationToken;

use crate::{
    broadcast::{BroadcastGroup, EndpointSendResult},
    error::{AlreadyRunningError, BroadcastError, SendError, SubscribeError},
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

    /// Send a message to every member of `group`, fire-and-forget.
    ///
    /// The communication backend resolves the group into its current members at send time, and
    /// each member then receives the message exactly as if it had been passed to
    /// [`send`](Self::send): encrypted over that endpoint's own session.
    ///
    /// Returns an error, without sending anything, if the group cannot be resolved. Otherwise
    /// returns one [`EndpointSendResult`] per resolved endpoint, in resolution order. A failed send
    /// to one endpoint, including [`SendError::Unreachable`], does not stop delivery to the others.
    async fn broadcast(
        &self,
        group: BroadcastGroup,
        payload: Vec<u8>,
        topic: Option<String>,
    ) -> Result<Vec<EndpointSendResult>, BroadcastError>;

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

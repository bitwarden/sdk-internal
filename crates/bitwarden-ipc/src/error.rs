use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::rpc::error::RpcError;

/// Classifies an IPC error as either fatal or recoverable.
///
/// The IPC client runs a single long-lived processing loop that is shared across every peer and
/// every message. Historically *any* transport or crypto error tore that loop down, which meant a
/// single transient failure (a handshake timeout, a peer disconnecting mid-send, a malformed
/// frame) permanently disabled the shared client and it never recovered.
///
/// This trait lets each layer classify its own errors so the client can distinguish the two cases:
/// - **Fatal** (`is_fatal() == true`): the client can no longer make progress, so the processing
///   loop should stop.
/// - **Recoverable** (`is_fatal() == false`): only the current operation failed, so the client
///   should stay running and continue processing other messages.
///
/// Implementations should classify errors at construction, where the most context is available,
/// and default ambiguous cases to recoverable. Failing open keeps the shared client alive, which
/// is almost always the safer choice.
pub trait IpcErrorKind {
    /// Returns `true` if the error is fatal and the IPC client should stop processing messages, or
    /// `false` if the error is recoverable and the client should keep running.
    fn is_fatal(&self) -> bool;
}

impl IpcErrorKind for std::convert::Infallible {
    fn is_fatal(&self) -> bool {
        // `Infallible` can never be constructed, so this is unreachable.
        match *self {}
    }
}

impl IpcErrorKind for String {
    fn is_fatal(&self) -> bool {
        // String errors carry no structured recoverability information. The IPC backends that use
        // them (e.g. the WASM communication backend) have no genuinely non-recoverable send or
        // receive errors today, so treat them as recoverable to keep the shared client alive. If a
        // backend ever needs to signal a fatal error, it should use a structured error type that
        // implements [`IpcErrorKind`] with a real fatal/recoverable distinction instead.
        false
    }
}

#[cfg(any(test, feature = "test-support"))]
impl IpcErrorKind for () {
    fn is_fatal(&self) -> bool {
        false
    }
}

/// Error returned by [`IpcClient::start`](crate::IpcClient::start). Indicates that the IPC client
/// is already running.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("IPC client is already running")]
#[bitwarden_error(basic)]
pub struct AlreadyRunningError;

/// Error returned by [`IpcClient::send`](crate::IpcClient::send). Wraps the underlying transport
/// error as a string.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("{0}")]
pub struct SendError(pub(crate) String);

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[bitwarden_error(flat)]
#[allow(missing_docs)]
pub enum SubscribeError {
    #[error("The IPC processing thread is not running")]
    NotStarted,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[bitwarden_error(flat)]
#[allow(missing_docs)]
pub enum ReceiveError {
    #[error("Failed to subscribe to the IPC channel: {0}")]
    Channel(#[from] tokio::sync::broadcast::error::RecvError),

    #[error("Timed out while waiting for a message: {0}")]
    Timeout(#[from] bitwarden_threading::time::ElapsedError),

    #[error("Cancelled while waiting for a message")]
    Cancelled,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[bitwarden_error(flat)]
#[allow(missing_docs)]
pub enum TypedReceiveError {
    #[error("Failed to subscribe to the IPC channel: {0}")]
    Channel(#[from] tokio::sync::broadcast::error::RecvError),

    #[error("Timed out while waiting for a message: {0}")]
    Timeout(#[from] bitwarden_threading::time::ElapsedError),

    #[error("Cancelled while waiting for a message")]
    Cancelled,

    #[error("Typing error: {0}")]
    Typing(String),
}

impl From<ReceiveError> for TypedReceiveError {
    fn from(value: ReceiveError) -> Self {
        match value {
            ReceiveError::Channel(e) => TypedReceiveError::Channel(e),
            ReceiveError::Timeout(e) => TypedReceiveError::Timeout(e),
            ReceiveError::Cancelled => TypedReceiveError::Cancelled,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
#[bitwarden_error(flat)]
#[allow(missing_docs)]
pub enum RequestError {
    #[error(transparent)]
    Subscribe(#[from] SubscribeError),

    #[error(transparent)]
    Receive(#[from] TypedReceiveError),

    #[error("Timed out while waiting for a message: {0}")]
    Timeout(#[from] bitwarden_threading::time::ElapsedError),

    #[error("Failed to send message: {0}")]
    Send(String),

    #[error("Error occurred on the remote target: {0}")]
    Rpc(#[from] RpcError),
}

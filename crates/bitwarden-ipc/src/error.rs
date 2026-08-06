use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::rpc::error::RpcError;

/// Classification of an IPC error, returned by [`IpcErrorKind::kind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// The client can no longer make progress, so the shared processing loop should stop.
    Fatal,
    /// The destination could not be reached (e.g. the peer transport is not connected);
    /// The client should continue to process messages. A peer may become reachable later.
    Unreachable,
    /// Any other, recoverable failure: only the current operation failed, so the client should stay
    /// running and continue processing other messages.
    Other,
}

/// Classifies an IPC error into an [`ErrorKind`].
///
/// The IPC client runs a single long-lived processing loop that is shared across every peer and
/// every message. Historically *any* transport or crypto error tore that loop down, which meant a
/// single transient failure (a handshake timeout, a peer disconnecting mid-send, a malformed
/// frame) permanently disabled the shared client and it never recovered.
///
/// This trait lets each layer classify its own errors so the client can distinguish the cases:
/// - [`ErrorKind::Fatal`]: the client can no longer make progress, so the processing loop should
///   stop.
/// - [`ErrorKind::Unreachable`] and [`ErrorKind::Other`]: only the current operation failed, so the
///   client should stay running and continue processing other messages.
///
/// Implementations should classify errors at construction, where the most context is available,
/// and default ambiguous cases to [`ErrorKind::Other`]. Failing open keeps the shared client alive,
/// which is almost always the safer choice.
pub trait IpcErrorKind {
    /// Classifies the error so the IPC client can decide whether to stop the processing loop or
    /// keep running.
    fn kind(&self) -> ErrorKind;
}

impl IpcErrorKind for std::convert::Infallible {
    fn kind(&self) -> ErrorKind {
        // `Infallible` can never be constructed, so this is unreachable.
        match *self {}
    }
}

#[cfg(any(test, feature = "test-support"))]
impl IpcErrorKind for () {
    fn kind(&self) -> ErrorKind {
        ErrorKind::Other
    }
}

/// Error returned by [`IpcClient::start`](crate::IpcClient::start). Indicates that the IPC client
/// is already running.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("IPC client is already running")]
#[bitwarden_error(basic)]
pub struct AlreadyRunningError;

/// Error returned by [`IpcClient::send`](crate::IpcClient::send).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SendError {
    /// The destination could not be reached (e.g. the peer transport is not connected).
    #[error("Destination unreachable")]
    Unreachable,
    /// Any other send failure, carrying the underlying error's debug representation.
    #[error("{0}")]
    Other(String),
}

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

    #[error("Destination unreachable")]
    Unreachable,

    #[error("Error occurred on the remote target: {0}")]
    Rpc(#[from] RpcError),
}

impl From<SendError> for RequestError {
    fn from(error: SendError) -> Self {
        match error {
            SendError::Unreachable => RequestError::Unreachable,
            SendError::Other(message) => RequestError::Send(message),
        }
    }
}

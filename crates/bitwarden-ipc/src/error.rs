use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::rpc::error::RpcError;

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
    Timeout(#[from] tokio::time::error::Elapsed),

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
    Timeout(#[from] tokio::time::error::Elapsed),

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
    Timeout(#[from] tokio::time::error::Elapsed),

    #[error("Failed to send message: {0}")]
    Send(String),

    #[error("Error occured on the remote target: {0}")]
    Rpc(#[from] RpcError),
}

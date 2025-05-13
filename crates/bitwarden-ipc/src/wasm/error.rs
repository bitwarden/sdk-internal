use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::{ipc_client::RequestError, rpc::error::RpcError};

#[derive(Debug, Error, PartialEq, Eq)]
#[bitwarden_error(flat, export_as = "RequestError")]
pub enum JsRequestError {
    #[error("Failed to subscribe to messages: {0}")]
    Subscribe(String),

    #[error("Failed to receive message: {0}")]
    Receive(String),

    #[error("Timed out while waiting for message")]
    Timeout,

    #[error("Failed to send message: {0}")]
    Send(String),

    #[error(transparent)]
    RpcError(RpcError),
}

impl<SendError> From<RequestError<SendError>> for JsRequestError
where
    SendError: std::fmt::Display,
{
    fn from(err: RequestError<SendError>) -> Self {
        match err {
            RequestError::Subscribe(err) => JsRequestError::Subscribe(err.to_string()),
            RequestError::Receive(err) => JsRequestError::Receive(err.to_string()),
            RequestError::Timeout(_) => JsRequestError::Timeout,
            RequestError::Send(err) => JsRequestError::Send(err.to_string()),
            RequestError::RpcError(err) => JsRequestError::RpcError(err),
        }
    }
}

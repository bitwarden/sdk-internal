use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, Clone, Serialize, Deserialize)]
pub enum RpcError<HandlerError> {
    #[error("Failed to read request: {0}")]
    RequestDeserializationError(String),

    #[error("Failed to serialize request: {0}")]
    RequestSerializationError(String),

    #[error("Failed to read response: {0}")]
    ResponseDeserializationError(String),

    #[error("Failed to serialize response: {0}")]
    ResponseSerializationError(String),

    #[error("Request could not be completed because no handler has been registered for")]
    NoHandlerFound,

    #[error("Error occured while executing the request: {0}")]
    HandlerError(HandlerError),
}

impl<HandlerError> RpcError<HandlerError>
where
    HandlerError: Serialize,
{
    pub(crate) fn serialize(self) -> Vec<u8> {
        serde_json::to_vec(&self).expect("Serializing RpcError should not fail")
    }
}

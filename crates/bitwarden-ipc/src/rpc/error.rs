use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::serde_utils;

#[derive(Debug, Error, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RpcError {
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
}

impl RpcError {
    pub(crate) fn to_vec(&self) -> Vec<u8> {
        serde_utils::to_vec(&self).expect("Serializing RpcError should not fail")
    }
}

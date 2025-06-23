use thiserror::Error;

#[derive(Debug, Error)]
pub enum HandleRpcRequestError {
    #[error("Failed to deserialize request message: {0}")]
    Deserialize(String),

    #[error("Failed to serialize response message: {0}")]
    Serialize(String),
}

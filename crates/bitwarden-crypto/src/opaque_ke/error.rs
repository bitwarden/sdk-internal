use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify_next::Tsify;

#[derive(Debug, Error, Deserialize, Serialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum OpaqueError {
    #[error("Error creating message {0}")]
    Message(String),
    #[error("Error deserializing message")]
    Deserialize,
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Opaque protocol error {0}")]
    Protocol(String),
}

impl From<opaque_ke::errors::ProtocolError> for OpaqueError {
    fn from(error: opaque_ke::errors::ProtocolError) -> Self {
        Self::Protocol(error.to_string())
    }
}

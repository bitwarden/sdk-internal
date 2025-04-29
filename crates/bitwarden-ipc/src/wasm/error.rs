use bitwarden_error::bitwarden_error;
use thiserror::Error;
use wasm_bindgen::prelude::*;

use crate::error::{ReceiveError, SendError};

#[derive(Debug, Error)]
#[bitwarden_error(flat, export_as = "SendError")]
pub enum JsSendError {
    #[error("Failed to process message: {0}")]
    Crypto(String),

    #[error("Failed to send message: {0}")]
    Communication(String),
}

#[derive(Debug, Error)]
#[bitwarden_error(flat, export_as = "ReceiveError")]
pub enum JsReceiveError {
    #[error("The receive operation timed out")]
    Timeout,

    #[error("Failed to process message: {0}")]
    Crypto(String),

    #[error("Failed to send message: {0}")]
    Communication(String),
}

impl From<SendError<String, String>> for JsSendError {
    fn from(error: SendError<String, String>) -> Self {
        match error {
            SendError::Crypto(e) => JsSendError::Crypto(e),
            SendError::Communication(e) => JsSendError::Communication(e),
        }
    }
}

impl From<ReceiveError<String, String>> for JsReceiveError {
    fn from(error: ReceiveError<String, String>) -> Self {
        match error {
            ReceiveError::Timeout => JsReceiveError::Timeout,
            ReceiveError::Crypto(e) => JsReceiveError::Crypto(e),
            ReceiveError::Communication(e) => JsReceiveError::Communication(e),
        }
    }
}

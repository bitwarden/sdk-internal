use wasm_bindgen::prelude::*;

use crate::error::{ReceiveError, SendError};

// TODO: Expose the error types to JS

#[wasm_bindgen(js_name = SendError)]
pub struct JsSendError {
    #[allow(dead_code)]
    crypto_error: Option<JsValue>,
    #[allow(dead_code)]
    communication_error: Option<JsValue>,
}

#[wasm_bindgen(js_class = SendError)]
impl JsSendError {
    pub fn debug(&self) -> String {
        if let Some(e) = &self.crypto_error {
            format!("Crypto error: {:?}", e)
        } else if let Some(e) = &self.communication_error {
            format!("Communication error: {:?}", e)
        } else {
            "Unknown error".to_string()
        }
    }
}

#[wasm_bindgen(js_name = ReceiveError)]
pub struct JsReceiveError {
    #[allow(dead_code)]
    crypto_error: Option<JsValue>,
    #[allow(dead_code)]
    communication_error: Option<JsValue>,
}

#[wasm_bindgen(js_class = ReceiveError)]
impl JsReceiveError {
    pub fn debug(&self) -> String {
        if let Some(e) = &self.crypto_error {
            format!("Crypto error: {:?}", e)
        } else if let Some(e) = &self.communication_error {
            format!("Communication error: {:?}", e)
        } else {
            "Unknown error".to_string()
        }
    }
}

impl From<SendError<JsValue, JsValue>> for JsSendError {
    fn from(error: SendError<JsValue, JsValue>) -> Self {
        match error {
            SendError::CryptoError(e) => JsSendError {
                crypto_error: Some(e),
                communication_error: None,
            },
            SendError::CommunicationError(e) => JsSendError {
                crypto_error: None,
                communication_error: Some(e),
            },
        }
    }
}

impl From<ReceiveError<JsValue, JsValue>> for JsReceiveError {
    fn from(error: ReceiveError<JsValue, JsValue>) -> Self {
        match error {
            ReceiveError::CryptoError(e) => JsReceiveError {
                crypto_error: Some(e),
                communication_error: None,
            },
            ReceiveError::CommunicationError(e) => JsReceiveError {
                crypto_error: None,
                communication_error: Some(e),
            },
        }
    }
}

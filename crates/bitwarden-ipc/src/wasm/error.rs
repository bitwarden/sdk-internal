use wasm_bindgen::prelude::*;

use crate::error::{ReceiveError, SendError};

// We're not using bitwarden_error here because we want to return the raw JsValue error
// (bitwarden_error would try to serialize it with tsify and serde)

#[wasm_bindgen(js_name = SendError)]
pub struct JsSendError {
    #[wasm_bindgen(getter_with_clone)]
    pub crypto_error: JsValue,
    #[wasm_bindgen(getter_with_clone)]
    pub communication_error: JsValue,
}

#[wasm_bindgen(js_name = ReceiveError)]
pub struct JsReceiveError {
    #[wasm_bindgen(getter_with_clone)]
    pub crypto_error: JsValue,
    #[wasm_bindgen(getter_with_clone)]
    pub communication_error: JsValue,
}

impl From<SendError<JsValue, JsValue>> for JsSendError {
    fn from(error: SendError<JsValue, JsValue>) -> Self {
        match error {
            SendError::CryptoError(e) => JsSendError {
                crypto_error: e,
                communication_error: JsValue::UNDEFINED,
            },
            SendError::CommunicationError(e) => JsSendError {
                crypto_error: JsValue::UNDEFINED,
                communication_error: e,
            },
        }
    }
}

impl From<ReceiveError<JsValue, JsValue>> for JsReceiveError {
    fn from(error: ReceiveError<JsValue, JsValue>) -> Self {
        match error {
            ReceiveError::CryptoError(e) => JsReceiveError {
                crypto_error: e,
                communication_error: JsValue::UNDEFINED,
            },
            ReceiveError::CommunicationError(e) => JsReceiveError {
                crypto_error: JsValue::UNDEFINED,
                communication_error: e,
            },
        }
    }
}

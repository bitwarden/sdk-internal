use wasm_bindgen::prelude::*;

use crate::error::{ReceiveError, SendError};

// We're not using bitwarden_error here because we want to return the raw JsValue error
// (bitwarden_error would try to serialize it with tsify and serde)

#[allow(missing_docs)]
#[wasm_bindgen(js_name = SendError)]
pub struct JsSendError {
    #[wasm_bindgen(getter_with_clone)]
    pub crypto: JsValue,
    #[wasm_bindgen(getter_with_clone)]
    pub communication: JsValue,
}

#[allow(missing_docs)]
#[wasm_bindgen(js_name = ReceiveError)]
pub struct JsReceiveError {
    pub timeout: bool,
    #[wasm_bindgen(getter_with_clone)]
    pub crypto: JsValue,
    #[wasm_bindgen(getter_with_clone)]
    pub communication: JsValue,
}

impl From<SendError<JsValue, JsValue>> for JsSendError {
    fn from(error: SendError<JsValue, JsValue>) -> Self {
        match error {
            SendError::Crypto(e) => JsSendError {
                crypto: e,
                communication: JsValue::UNDEFINED,
            },
            SendError::Communication(e) => JsSendError {
                crypto: JsValue::UNDEFINED,
                communication: e,
            },
        }
    }
}

impl From<ReceiveError<JsValue, JsValue>> for JsReceiveError {
    fn from(error: ReceiveError<JsValue, JsValue>) -> Self {
        match error {
            ReceiveError::Timeout => JsReceiveError {
                timeout: true,
                crypto: JsValue::UNDEFINED,
                communication: JsValue::UNDEFINED,
            },
            ReceiveError::Crypto(e) => JsReceiveError {
                timeout: false,
                crypto: e,
                communication: JsValue::UNDEFINED,
            },
            ReceiveError::Communication(e) => JsReceiveError {
                timeout: false,
                crypto: JsValue::UNDEFINED,
                communication: e,
            },
        }
    }
}

use bitwarden_error::bitwarden_error;
use thiserror::Error;
use tsify_next::serde_wasm_bindgen;
use wasm_bindgen::prelude::*;

use crate::{
    message::{IncomingMessage, OutgoingMessage},
    traits::CommunicationBackend,
};

#[derive(Debug, Error)]
#[bitwarden_error(basic)]
#[error("Failed to deserialize incoming message: {0}")]
pub struct DeserializeError(String);

#[wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export interface CommunicationBackend {
    send(message: OutgoingMessage): Promise<void>;
    receive(): Promise<IncomingMessage>;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = CommunicationBackend, typescript_type = "CommunicationBackend")]
    pub type JsCommunicationBackend;

    #[wasm_bindgen(catch, method, structural)]
    pub async fn send(
        this: &JsCommunicationBackend,
        message: OutgoingMessage,
    ) -> Result<(), JsValue>;

    #[wasm_bindgen(catch, method, structural)]
    pub async fn receive(this: &JsCommunicationBackend) -> Result<JsValue, JsValue>;
}

impl CommunicationBackend for JsCommunicationBackend {
    type SendError = JsValue;
    type ReceiveError = JsValue;

    async fn send(&self, message: OutgoingMessage) -> Result<(), Self::SendError> {
        self.send(message).await
    }

    async fn receive(&self) -> Result<IncomingMessage, Self::ReceiveError> {
        let js_value = self.receive().await?;
        let message: IncomingMessage = serde_wasm_bindgen::from_value(js_value)
            .map_err(|e| DeserializeError(e.to_string()))?;
        Ok(message)
    }
}

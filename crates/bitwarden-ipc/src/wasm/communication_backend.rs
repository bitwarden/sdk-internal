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

#[derive(Debug, Error)]
#[bitwarden_error(basic)]
#[error("Incoming message channel failed: {0}")]
pub struct ChannelError(String);

#[wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export interface CommunicationBackendSender {
    send(message: OutgoingMessage): Promise<void>;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = CommunicationBackendSender, typescript_type = "CommunicationBackendSender")]
    pub type JsCommunicationBackendSender;

    #[wasm_bindgen(catch, method, structural)]
    pub async fn send(
        this: &JsCommunicationBackendSender,
        message: OutgoingMessage,
    ) -> Result<(), JsValue>;

    #[wasm_bindgen(catch, method, structural)]
    pub async fn receive(this: &JsCommunicationBackendSender) -> Result<JsValue, JsValue>;
}

#[wasm_bindgen]
pub struct JsCommunicationBackend {
    sender: JsCommunicationBackendSender,
    receive_rx: tokio::sync::broadcast::Receiver<IncomingMessage>,
    receive_tx: tokio::sync::broadcast::Sender<IncomingMessage>,
}

#[wasm_bindgen]
impl JsCommunicationBackend {
    pub fn new(sender: JsCommunicationBackendSender) -> Self {
        let (receive_tx, receive_rx) = tokio::sync::broadcast::channel(20);
        Self {
            sender,
            receive_rx,
            receive_tx,
        }
    }

    /// JavaScript function to provide a received message to the backend/IPC framework.
    pub fn receive_tx(&self, message: JsValue) -> Result<(), JsValue> {
        let message: IncomingMessage =
            serde_wasm_bindgen::from_value(message).map_err(|e| DeserializeError(e.to_string()))?;
        self.receive_tx
            .send(message)
            .map_err(|e| ChannelError(e.to_string()))?;
        Ok(())
    }
}

impl CommunicationBackend for JsCommunicationBackend {
    type SendError = JsValue;
    type ReceiveError = JsValue;

    async fn send(&self, message: OutgoingMessage) -> Result<(), Self::SendError> {
        self.sender.send(message).await
    }

    async fn receive(&self) -> Result<IncomingMessage, Self::ReceiveError> {
        let mut receive_rx = self.receive_rx.resubscribe();
        let message = receive_rx
            .recv()
            .await
            .map_err(|e| ChannelError(e.to_string()))?;
        Ok(message)
    }
}

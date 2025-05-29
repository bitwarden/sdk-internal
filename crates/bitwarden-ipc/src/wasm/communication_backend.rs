use bitwarden_error::bitwarden_error;
use thiserror::Error;
use tokio::sync::RwLock;
use wasm_bindgen::prelude::*;

use crate::{
    message::{IncomingMessage, OutgoingMessage},
    traits::{CommunicationBackend, CommunicationBackendReceiver},
};

#[allow(missing_docs)]
#[derive(Debug, Error)]
#[bitwarden_error(basic)]
#[error("Failed to deserialize incoming message: {0}")]
pub struct DeserializeError(String);

#[allow(missing_docs)]
#[derive(Debug, Error)]
#[bitwarden_error(basic)]
#[error("Incoming message channel failed: {0}")]
pub struct ChannelError(String);

#[wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export interface IpcCommunicationBackendSender {
    send(message: OutgoingMessage): Promise<void>;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[allow(missing_docs)]
    #[wasm_bindgen(js_name = IpcCommunicationBackendSender, typescript_type = "IpcCommunicationBackendSender")]
    pub type JsCommunicationBackendSender;

    #[allow(missing_docs)]
    #[wasm_bindgen(catch, method, structural)]
    pub async fn send(
        this: &JsCommunicationBackendSender,
        message: OutgoingMessage,
    ) -> Result<(), JsValue>;

    #[allow(missing_docs)]
    #[wasm_bindgen(catch, method, structural)]
    pub async fn receive(this: &JsCommunicationBackendSender) -> Result<JsValue, JsValue>;
}

#[allow(missing_docs)]
#[wasm_bindgen(js_name = IpcCommunicationBackend)]
pub struct JsCommunicationBackend {
    sender: JsCommunicationBackendSender,
    receive_rx: tokio::sync::broadcast::Receiver<IncomingMessage>,
    receive_tx: tokio::sync::broadcast::Sender<IncomingMessage>,
}

#[wasm_bindgen(js_class = IpcCommunicationBackend)]
impl JsCommunicationBackend {
    #[allow(missing_docs)]
    #[wasm_bindgen(constructor)]
    pub fn new(sender: JsCommunicationBackendSender) -> Self {
        let (receive_tx, receive_rx) = tokio::sync::broadcast::channel(20);
        Self {
            sender,
            receive_rx,
            receive_tx,
        }
    }

    /// JavaScript function to provide a received message to the backend/IPC framework.
    pub fn deliver_message(&self, message: IncomingMessage) -> Result<(), JsValue> {
        self.receive_tx
            .send(message)
            .map_err(|e| ChannelError(e.to_string()))?;
        Ok(())
    }
}

impl CommunicationBackend for JsCommunicationBackend {
    type SendError = JsValue;
    type Receiver = RwLock<tokio::sync::broadcast::Receiver<IncomingMessage>>;

    async fn send(&self, message: OutgoingMessage) -> Result<(), Self::SendError> {
        self.sender.send(message).await
    }

    async fn subscribe(&self) -> Self::Receiver {
        RwLock::new(self.receive_rx.resubscribe())
    }
}

impl CommunicationBackendReceiver for RwLock<tokio::sync::broadcast::Receiver<IncomingMessage>> {
    type ReceiveError = JsValue;

    async fn receive(&self) -> Result<IncomingMessage, Self::ReceiveError> {
        Ok(self
            .write()
            .await
            .recv()
            .await
            .map_err(|e| ChannelError(e.to_string()))?)
    }
}

use std::sync::Arc;

use bitwarden_error::bitwarden_error;
use bitwarden_threading::ThreadBoundRunner;
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
    /// JavaScript interface for handling outgoing messages from the IPC framework.
    #[wasm_bindgen(js_name = IpcCommunicationBackendSender, typescript_type = "IpcCommunicationBackendSender")]
    pub type JsCommunicationBackendSender;

    /// Used by the IPC framework to send an outgoing message.
    #[wasm_bindgen(catch, method, structural)]
    pub async fn send(
        this: &JsCommunicationBackendSender,
        message: OutgoingMessage,
    ) -> Result<(), JsValue>;

    /// Used by JavaScript to provide an incoming message to the IPC framework.
    #[wasm_bindgen(catch, method, structural)]
    pub async fn receive(this: &JsCommunicationBackendSender) -> Result<JsValue, JsValue>;
}

/// JavaScript implementation of the `CommunicationBackend` trait for IPC communication.
#[wasm_bindgen(js_name = IpcCommunicationBackend)]
pub struct JsCommunicationBackend {
    sender: Arc<ThreadBoundRunner<JsCommunicationBackendSender>>,
    receive_rx: tokio::sync::broadcast::Receiver<IncomingMessage>,
    receive_tx: tokio::sync::broadcast::Sender<IncomingMessage>,
}

impl Clone for JsCommunicationBackend {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            receive_rx: self.receive_rx.resubscribe(),
            receive_tx: self.receive_tx.clone(),
        }
    }
}

#[wasm_bindgen(js_class = IpcCommunicationBackend)]
impl JsCommunicationBackend {
    /// Creates a new instance of the JavaScript communication backend.
    #[wasm_bindgen(constructor)]
    pub fn new(sender: JsCommunicationBackendSender) -> Self {
        let (receive_tx, receive_rx) = tokio::sync::broadcast::channel(20);
        Self {
            sender: Arc::new(ThreadBoundRunner::new(sender)),
            receive_rx,
            receive_tx,
        }
    }

    /// Used by JavaScript to provide an incoming message to the IPC framework.
    pub fn receive(&self, message: IncomingMessage) -> Result<(), JsValue> {
        self.receive_tx
            .send(message)
            .map_err(|e| ChannelError(e.to_string()))?;
        Ok(())
    }
}

impl CommunicationBackend for JsCommunicationBackend {
    type SendError = String;
    type Receiver = RwLock<tokio::sync::broadcast::Receiver<IncomingMessage>>;

    async fn send(&self, message: OutgoingMessage) -> Result<(), Self::SendError> {
        let result = self
            .sender
            .run_in_thread(|sender| async move {
                sender.send(message).await.map_err(|e| format!("{:?}", e))
            })
            .await;

        result.map_err(|e| e.to_string())?
    }

    async fn subscribe(&self) -> Self::Receiver {
        RwLock::new(self.receive_rx.resubscribe())
    }
}

impl CommunicationBackendReceiver for RwLock<tokio::sync::broadcast::Receiver<IncomingMessage>> {
    type ReceiveError = String;

    async fn receive(&self) -> Result<IncomingMessage, Self::ReceiveError> {
        self.write().await.recv().await.map_err(|e| e.to_string())
    }
}

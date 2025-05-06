use std::rc::Rc;

use bitwarden_error::bitwarden_error;
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};
use wasm_bindgen::prelude::*;

use crate::{
    constants::CHANNEL_BUFFER_CAPACITY,
    message::{IncomingMessage, OutgoingMessage},
    traits::{CommunicationBackend, CommunicationBackendReceiver},
};

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
    #[wasm_bindgen(js_name = IpcCommunicationBackendSender, typescript_type = "IpcCommunicationBackendSender")]
    pub type JsCommunicationBackendSender;

    #[wasm_bindgen(catch, method, structural)]
    pub async fn send(
        this: &JsCommunicationBackendSender,
        message: OutgoingMessage,
    ) -> Result<(), JsValue>;

    #[wasm_bindgen(catch, method, structural)]
    pub async fn receive(this: &JsCommunicationBackendSender) -> Result<JsValue, JsValue>;
}

#[wasm_bindgen(js_name = IpcCommunicationBackend)]
pub struct JsCommunicationBackend {
    sender: Rc<Mutex<JsCommunicationBackendSender>>,
    receive_rx: tokio::sync::broadcast::Receiver<IncomingMessage>,
    receive_tx: tokio::sync::broadcast::Sender<IncomingMessage>,
}

#[wasm_bindgen(js_class = IpcCommunicationBackend)]
impl JsCommunicationBackend {
    #[wasm_bindgen(constructor)]
    pub fn new(sender: JsCommunicationBackendSender) -> Self {
        let (receive_tx, receive_rx) = tokio::sync::broadcast::channel(20);
        Self {
            sender: Rc::new(Mutex::new(sender)),
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

impl From<&JsCommunicationBackend> for ThreadSafeJsCommunicationBackend {
    fn from(backend: &JsCommunicationBackend) -> Self {
        let (cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);
        let (send_tx, mut send_rx) = tokio::sync::mpsc::channel(CHANNEL_BUFFER_CAPACITY);
        let sender = backend.sender.clone();

        wasm_bindgen_futures::spawn_local(async move {
            loop {
                tokio::select! {
                    _ = cancel_rx.changed() => {
                        log::debug!("ThreadSafeJsCommunicationBackend cancelled");
                        break;
                    }
                    message = send_rx.recv() => {
                        match message {
                            Some(message) => {
                                let result = sender.lock().await.send(message).await;
                                if let Err(e) = result {
                                    log::error!("Failed to send IPC message: {:?}", e);
                                }
                            }
                            None => {
                                log::debug!("ThreadSafeJsCommunicationBackend send_rx channel closed");
                                break
                            },
                        }
                    }
                }

                log::debug!("ThreadSafeJsCommunicationBackend thread shutting down");
            }
        });

        ThreadSafeJsCommunicationBackend {
            send_tx,
            receive_rx: backend.receive_rx.resubscribe(),
            cancel_tx,
        }
    }
}

/// A thread-safe version of the `JsCommunicationBackend` that can be used in a multi-threaded
/// environment, i.e. it implements `Send + Sync`.
pub struct ThreadSafeJsCommunicationBackend {
    send_tx: tokio::sync::mpsc::Sender<OutgoingMessage>,
    receive_rx: tokio::sync::broadcast::Receiver<IncomingMessage>,
    cancel_tx: tokio::sync::watch::Sender<bool>,
}

impl CommunicationBackend for ThreadSafeJsCommunicationBackend {
    type SendError = String;
    type Receiver = RwLock<tokio::sync::broadcast::Receiver<IncomingMessage>>;

    async fn send(&self, message: OutgoingMessage) -> Result<(), Self::SendError> {
        self.send_tx.send(message).await.map_err(|e| e.to_string())
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

impl Drop for ThreadSafeJsCommunicationBackend {
    fn drop(&mut self) {
        // Cancel the thread
        let _ = self.cancel_tx.send(true);
    }
}

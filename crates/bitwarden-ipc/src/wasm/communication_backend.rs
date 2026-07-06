use std::sync::Arc;

use bitwarden_error::bitwarden_error;
use bitwarden_threading::ThreadBoundRunner;
use thiserror::Error;
use tokio::sync::RwLock;
use wasm_bindgen::prelude::*;

use crate::{
    error::IpcErrorKind,
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

/// Error type for the WASM communication backend's send and receive operations.
///
/// Distinguishes recoverable failures (which leave the shared IPC client running) from the fatal
/// closed-channel state. Without this distinction the client's processing loop would treat a
/// permanently-closed broadcast channel as recoverable and busy-loop on it, since a closed channel
/// returns an error immediately and forever without ever awaiting.
#[derive(Debug, Error)]
pub enum WasmCommunicationError {
    /// An error returned by the JavaScript backend (e.g. a failed send). Recoverable: the IPC
    /// client keeps running so future operations can succeed.
    #[error("{0}")]
    Js(String),

    /// The incoming message receiver fell behind and `0` messages were dropped. Recoverable: the
    /// next receive resumes normally.
    #[error("incoming message channel lagged, {0} messages were dropped")]
    Lagged(u64),

    /// The communication channel was closed because all senders were dropped. This is fatal: the
    /// IPC client's processing loop stops cleanly instead of busy-looping on the closed channel.
    #[error("incoming message channel closed")]
    Closed,
}

impl IpcErrorKind for WasmCommunicationError {
    fn is_fatal(&self) -> bool {
        matches!(self, WasmCommunicationError::Closed)
    }
}

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
    type SendError = WasmCommunicationError;
    type Receiver = RwLock<tokio::sync::broadcast::Receiver<IncomingMessage>>;

    async fn send(&self, message: OutgoingMessage) -> Result<(), Self::SendError> {
        // Both the thread-runner failure and the JS-side send failure are treated as recoverable:
        // a single failed send must not tear down the shared IPC client.
        self.sender
            .run_in_thread(|sender| async move {
                sender.send(message).await.map_err(|e| format!("{e:?}"))
            })
            .await
            .map_err(|e| WasmCommunicationError::Js(e.to_string()))?
            .map_err(WasmCommunicationError::Js)
    }

    async fn subscribe(&self) -> Self::Receiver {
        RwLock::new(self.receive_rx.resubscribe())
    }
}

impl CommunicationBackendReceiver for RwLock<tokio::sync::broadcast::Receiver<IncomingMessage>> {
    type ReceiveError = WasmCommunicationError;

    async fn receive(&self) -> Result<IncomingMessage, Self::ReceiveError> {
        use tokio::sync::broadcast::error::RecvError;

        self.write().await.recv().await.map_err(|e| match e {
            // All senders have been dropped; the channel can never produce another message and
            // `recv()` would return immediately forever. Treat this as fatal so the processing
            // loop stops instead of busy-looping.
            RecvError::Closed => WasmCommunicationError::Closed,
            // The receiver fell behind and missed `skipped` messages. The next `recv()` resumes
            // normally, so this is recoverable.
            RecvError::Lagged(skipped) => WasmCommunicationError::Lagged(skipped),
        })
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::{RwLock, broadcast};

    use super::*;
    use crate::{
        endpoint::{Endpoint, HostId, Source},
        error::IpcErrorKind,
    };

    fn test_message() -> IncomingMessage {
        IncomingMessage {
            payload: vec![],
            source: Source::BrowserBackground { id: HostId::Own },
            destination: Endpoint::BrowserBackground { id: HostId::Own },
            topic: None,
        }
    }

    #[tokio::test]
    async fn receive_returns_fatal_closed_when_all_senders_are_dropped() {
        let (tx, rx) = broadcast::channel::<IncomingMessage>(4);
        let receiver = RwLock::new(rx);

        // Dropping the only sender closes the channel permanently.
        drop(tx);

        let error = receiver.receive().await.unwrap_err();
        assert!(matches!(error, WasmCommunicationError::Closed));
        assert!(error.is_fatal());
    }

    #[tokio::test]
    async fn receive_returns_recoverable_lagged_when_receiver_falls_behind() {
        let (tx, rx) = broadcast::channel::<IncomingMessage>(1);
        let receiver = RwLock::new(rx);

        // Overflow the buffer without receiving so the next recv reports lag.
        for _ in 0..3 {
            tx.send(test_message()).expect("send should not fail");
        }

        let error = receiver.receive().await.unwrap_err();
        assert!(matches!(error, WasmCommunicationError::Lagged(_)));
        assert!(!error.is_fatal());
    }
}

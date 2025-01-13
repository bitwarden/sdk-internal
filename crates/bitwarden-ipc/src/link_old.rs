use bitwarden_error::prelude::*;
use thiserror::Error;
use tokio::sync::broadcast;

#[derive(Debug, Error)]
#[error(transparent)]
#[bitwarden_error(basic)]
pub struct SendError(#[from] broadcast::error::SendError<Vec<u8>>);

#[derive(Debug, Error)]
#[error(transparent)]
pub struct ReceiveError(#[from] broadcast::error::RecvError);

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

struct BroadcastPair {
    tx: broadcast::Sender<Vec<u8>>,
    // Store a receiver to keep the channel alive
    _rx: broadcast::Receiver<Vec<u8>>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct Link {
    incoming: BroadcastPair,
    outgoing: BroadcastPair,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl Link {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(100);
        let incoming = BroadcastPair { tx, _rx };

        let (tx, _rx) = broadcast::channel(100);
        let outgoing = BroadcastPair { tx, _rx };

        Self { incoming, outgoing }
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl Link {
    /// Starts an async loop that listens for outgoing data and sends it to the provided callback.
    /// Do not await this function, as that will block your thread until the link is closed.
    /// The callback should take a single argument, a Uint8Array, which contains the data to be sent.
    pub async fn start(&self, send: &js_sys::Function) {
        let mut outgoing = self.outgoing.tx.subscribe();
        loop {
            let data = outgoing.recv().await;
            if let Ok(data) = data {
                // Call the send function with the data
                let data = js_sys::Uint8Array::from(data.as_slice());
                send.call1(&JsValue::NULL, &data).unwrap();
            }
        }
    }

    /// Call this function when a message has been received from the other side of the link.
    /// This application will then process the message.
    pub async fn add(&self, data: Vec<u8>) -> Result<(), SendError> {
        self.incoming.tx.send(data)?;
        Ok(())
    }
}

impl Link {
    pub async fn send(&self, data: Vec<u8>) -> Result<(), SendError> {
        self.outgoing.tx.send(data)?;
        Ok(())
    }

    pub async fn receive(&self) -> Result<Vec<u8>, ReceiveError> {
        let tx = self.incoming.tx.clone();
        let mut rx = tx.subscribe();
        let data = rx.recv().await?;
        Ok(data)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Vec<u8>> {
        self.outgoing.tx.subscribe()
    }
}

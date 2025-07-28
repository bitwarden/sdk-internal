use futures_util::{stream::SplitSink, stream::SplitStream, SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_tungstenite_wasm::{connect, Message, WebSocketStream};
use uuid::Uuid;

pub trait HubClient {
    async fn new() -> Self;
    async fn connect(&mut self) -> Result<Uuid, TransportError>;
    async fn send_message(
        &mut self,
        message: Vec<u8>,
        destination: Uuid,
    ) -> Result<(), TransportError>;
    async fn receive_message(&mut self) -> Result<Payload, TransportError>;
    fn local_uuid(&self) -> Option<Uuid>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Payload {
    pub sender: Uuid,
    pub destination: Uuid,
    pub message: Vec<u8>,
}

#[derive(Debug)]
pub enum TransportError {
    ConnectionError,
    TimeoutError,
    SerializationError,
}

pub struct WebsocketHubClient {
    sender: Option<Arc<Mutex<SplitSink<WebSocketStream, Message>>>>,
    receiver: Option<Arc<Mutex<SplitStream<WebSocketStream>>>>,
    local_uuid: Option<Uuid>,
}

impl HubClient for WebsocketHubClient {
    async fn new() -> Self {
        WebsocketHubClient {
            sender: None,
            receiver: None,
            local_uuid: None,
        }
    }

    fn local_uuid(&self) -> Option<Uuid> {
        self.local_uuid
    }

    async fn connect(&mut self) -> Result<Uuid, TransportError> {
        let ws = connect("ws://localhost:9002")
            .await
            .map_err(|_| TransportError::ConnectionError)?;
        let (sender, receiver) = ws.split();

        println!("Connected to echo server.");

        // Store the sender and receiver
        self.sender = Some(Arc::new(Mutex::new(sender)));
        self.receiver = Some(Arc::new(Mutex::new(receiver)));

        // Receive the initial binary message containing the UUID
        let msg = {
            let mut receiver_guard = self.receiver.as_ref().unwrap().lock().await;
            receiver_guard
                .next()
                .await
                .ok_or(TransportError::ConnectionError)?
                .map_err(|_| TransportError::ConnectionError)?
        };

        println!("Received message: {:?}", msg);

        let uuid_bytes = match msg {
            Message::Binary(data) => data,
            _ => return Err(TransportError::ConnectionError),
        };

        // Parse the UUID from the binary data
        let uuid_str =
            String::from_utf8(uuid_bytes.to_vec()).map_err(|_| TransportError::ConnectionError)?;
        let local_uuid: Uuid = uuid_str
            .parse()
            .map_err(|_| TransportError::ConnectionError)?;
        println!("My UUID: {}", local_uuid);

        // Store the local UUID
        self.local_uuid = Some(local_uuid);
        Ok(local_uuid)
    }

    async fn send_message(
        &mut self,
        message: Vec<u8>,
        destination: Uuid,
    ) -> Result<(), TransportError> {
        if let Some(sender) = &self.sender {
            let message = Payload {
                sender: self.local_uuid.unwrap(),
                destination: destination,
                message: message,
            };

            // Encode the message with ciborium
            let mut buf = Vec::new();
            ciborium::into_writer(&message, &mut buf)
                .map_err(|_| TransportError::SerializationError)?;

            // Send the encoded message
            let mut sender_guard = sender.lock().await;
            sender_guard
                .send(Message::binary(buf))
                .await
                .map_err(|_| TransportError::ConnectionError)?;

            Ok(())
        } else {
            Err(TransportError::ConnectionError)
        }
    }

    async fn receive_message(&mut self) -> Result<Payload, TransportError> {
        if let Some(receiver) = &self.receiver {
            let mut receiver_guard = receiver.lock().await;

            let msg = receiver_guard
                .next()
                .await
                .ok_or(TransportError::ConnectionError)?
                .map_err(|_| TransportError::ConnectionError)?;

            match msg {
                Message::Binary(data) => {
                    // Decode the payload with ciborium
                    let payload: Payload = ciborium::from_reader(&data[..])
                        .map_err(|_| TransportError::SerializationError)?;
                    Ok(payload)
                }
                _ => Err(TransportError::ConnectionError),
            }
        } else {
            Err(TransportError::ConnectionError)
        }
    }
}

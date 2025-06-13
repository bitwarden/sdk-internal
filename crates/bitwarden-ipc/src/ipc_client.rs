use std::sync::Arc;

use bitwarden_error::bitwarden_error;
use bitwarden_threading::cancellation_token::CancellationToken;
use thiserror::Error;
use tokio::{select, sync::RwLock};

use crate::{
    constants::CHANNEL_BUFFER_CAPACITY,
    message::{IncomingMessage, OutgoingMessage, PayloadTypeName, TypedIncomingMessage},
    traits::{CommunicationBackend, CryptoProvider, SessionRepository},
};

/// An IPC client that handles communication between different components and clients.
/// It uses a crypto provider to encrypt and decrypt messages, a communication backend to send and
/// receive messages, and a session repository to persist sessions.
pub struct IpcClient<Crypto, Com, Ses>
where
    Crypto: CryptoProvider<Com, Ses>,
    Com: CommunicationBackend,
    Ses: SessionRepository<Crypto::Session>,
{
    crypto: Crypto,
    communication: Com,
    sessions: Ses,

    incoming: RwLock<Option<tokio::sync::broadcast::Receiver<IncomingMessage>>>,
    cancellation_token: RwLock<Option<CancellationToken>>,
}

/// A subscription to receive messages over IPC.
/// The subcription will start buffering messages after its creation and return them
/// when receive() is called. Messages received before the subscription was created will not be
/// returned.
pub struct IpcClientSubscription {
    receiver: tokio::sync::broadcast::Receiver<IncomingMessage>,
    topic: Option<String>,
}

/// A subscription to receive messages over IPC.
/// The subcription will start buffering messages after its creation and return them
/// when receive() is called. Messages received before the subscription was created will not be
/// returned.
pub struct IpcClientTypedSubscription<Payload: TryFrom<Vec<u8>> + PayloadTypeName>(
    IpcClientSubscription,
    std::marker::PhantomData<Payload>,
);

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[bitwarden_error(flat)]
#[allow(missing_docs)]
pub enum SubscribeError {
    #[error("The IPC processing thread is not running")]
    NotStarted,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[bitwarden_error(flat)]
#[allow(missing_docs)]
pub enum ReceiveError {
    #[error("Failed to subscribe to the IPC channel: {0}")]
    Channel(#[from] tokio::sync::broadcast::error::RecvError),

    #[error("Timed out while waiting for a message: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),

    #[error("Cancelled while waiting for a message")]
    Cancelled,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[bitwarden_error(flat)]
#[allow(missing_docs)]
pub enum TypedReceiveError {
    #[error("Failed to subscribe to the IPC channel: {0}")]
    Channel(#[from] tokio::sync::broadcast::error::RecvError),

    #[error("Timed out while waiting for a message: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),

    #[error("Cancelled while waiting for a message")]
    Cancelled,

    #[error("Typing error: {0}")]
    Typing(String),
}

impl From<ReceiveError> for TypedReceiveError {
    fn from(value: ReceiveError) -> Self {
        match value {
            ReceiveError::Channel(e) => TypedReceiveError::Channel(e),
            ReceiveError::Timeout(e) => TypedReceiveError::Timeout(e),
            ReceiveError::Cancelled => TypedReceiveError::Cancelled,
        }
    }
}

impl<Crypto, Com, Ses> IpcClient<Crypto, Com, Ses>
where
    Crypto: CryptoProvider<Com, Ses>,
    Com: CommunicationBackend,
    Ses: SessionRepository<Crypto::Session>,
{
    /// Create a new IPC client with the provided crypto provider, communication backend, and
    /// session repository.
    pub fn new(crypto: Crypto, communication: Com, sessions: Ses) -> Arc<Self> {
        Arc::new(Self {
            crypto,
            communication,
            sessions,

            incoming: RwLock::new(None),
            cancellation_token: RwLock::new(None),
        })
    }

    /// Start the IPC client, which will begin listening for incoming messages and processing them.
    /// This will be done in a separate task, allowing the client to receive messages
    /// asynchronously. The client will stop automatically if an error occurs during message
    /// processing or if the cancellation token is triggered.
    ///
    /// Note: The client can and will send messages in the background while it is running, even if
    /// no active subscriptions are present.
    pub async fn start(self: &Arc<Self>) {
        let cancellation_token = CancellationToken::new();
        self.cancellation_token
            .write()
            .await
            .replace(cancellation_token.clone());

        let com_receiver = self.communication.subscribe().await;
        let (client_tx, client_rx) = tokio::sync::broadcast::channel(CHANNEL_BUFFER_CAPACITY);

        self.incoming.write().await.replace(client_rx);

        let client = self.clone();
        let future = async move {
            loop {
                select! {
                    _ = cancellation_token.cancelled() => {
                        log::debug!("Cancellation signal received, stopping IPC client");
                        break;
                    }
                    received = client.crypto.receive(&com_receiver, &client.communication, &client.sessions) => {
                        match received {
                            Ok(message) => {
                                if client_tx.send(message).is_err() {
                                    log::error!("Failed to save incoming message");
                                    break;
                                };
                            }
                            Err(e) => {
                                log::error!("Error receiving message: {:?}", e);
                                break;
                            }
                        }
                    }
                }
            }
            log::debug!("IPC client shutting down");
            client.stop().await;
        };

        #[cfg(not(target_arch = "wasm32"))]
        tokio::spawn(future);

        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(future);
    }

    /// Check if the IPC client task is currently running.
    pub async fn is_running(self: &Arc<Self>) -> bool {
        let has_incoming = self.incoming.read().await.is_some();
        let has_cancellation_token = self.cancellation_token.read().await.is_some();
        has_incoming && has_cancellation_token
    }

    /// Stop the IPC client task. This will stop listening for incoming messages.
    pub async fn stop(self: &Arc<Self>) {
        let mut incoming = self.incoming.write().await;
        let _ = incoming.take();

        let mut cancellation_token = self.cancellation_token.write().await;
        if let Some(cancellation_token) = cancellation_token.take() {
            cancellation_token.cancel();
        }
    }

    /// Send a message
    pub async fn send(self: &Arc<Self>, message: OutgoingMessage) -> Result<(), Crypto::SendError> {
        let result = self
            .crypto
            .send(&self.communication, &self.sessions, message)
            .await;

        if result.is_err() {
            log::error!("Error sending message: {:?}", result);
            self.stop().await;
        }

        result
    }

    /// Create a subscription to receive messages, optionally filtered by topic.
    /// Setting the topic to `None` will receive all messages.
    pub async fn subscribe(
        self: &Arc<Self>,
        topic: Option<String>,
    ) -> Result<IpcClientSubscription, SubscribeError> {
        Ok(IpcClientSubscription {
            receiver: self
                .incoming
                .read()
                .await
                .as_ref()
                .ok_or(SubscribeError::NotStarted)?
                .resubscribe(),
            topic,
        })
    }

    /// Create a subscription to receive messages that can be deserialized into the provided payload
    /// type.
    pub async fn subscribe_typed<Payload>(
        self: &Arc<Self>,
    ) -> Result<IpcClientTypedSubscription<Payload>, SubscribeError>
    where
        Payload: TryFrom<Vec<u8>> + PayloadTypeName,
    {
        Ok(IpcClientTypedSubscription(
            self.subscribe(Some(Payload::name())).await?,
            std::marker::PhantomData,
        ))
    }
}

impl IpcClientSubscription {
    /// Receive a message, optionally filtering by topic.
    /// Setting the cancellation_token to `None` will wait indefinitely.
    pub async fn receive(
        &mut self,
        cancellation_token: Option<CancellationToken>,
    ) -> Result<IncomingMessage, ReceiveError> {
        let cancellation_token = cancellation_token.unwrap_or_default();

        loop {
            select! {
                _ = cancellation_token.cancelled() => {
                    return Err(ReceiveError::Cancelled)
                }
                result = self.receiver.recv() => {
                    let received = result?;
                    if self.topic.is_none() || received.topic == self.topic {
                        return Ok::<IncomingMessage, ReceiveError>(received);
                    }
                }
            }
        }
    }
}

impl<Payload, TryFromError> IpcClientTypedSubscription<Payload>
where
    Payload: TryFrom<Vec<u8>, Error = TryFromError> + PayloadTypeName,
    TryFromError: std::fmt::Display,
{
    /// Receive a message.
    /// Setting the cancellation_token to `None` will wait indefinitely.
    pub async fn receive(
        &mut self,
        cancellation_token: Option<CancellationToken>,
    ) -> Result<TypedIncomingMessage<Payload>, TypedReceiveError> {
        let received = self.0.receive(cancellation_token).await?;
        received
            .try_into()
            .map_err(|e: TryFromError| TypedReceiveError::Typing(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, time::Duration};

    use bitwarden_threading::time::sleep;
    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::{
        endpoint::Endpoint,
        traits::{
            tests::TestCommunicationBackend, InMemorySessionRepository, NoEncryptionCryptoProvider,
        },
    };

    struct TestCryptoProvider {
        /// Simulate a send result. Set to `None` wait indefinitely
        send_result: Option<Result<(), String>>,
        /// Simulate a receive result. Set to `None` wait indefinitely
        receive_result: Option<Result<IncomingMessage, String>>,
    }

    type TestSessionRepository = InMemorySessionRepository<String>;
    impl CryptoProvider<TestCommunicationBackend, TestSessionRepository> for TestCryptoProvider {
        type Session = String;
        type SendError = String;
        type ReceiveError = String;

        async fn receive(
            &self,
            _receiver: &<TestCommunicationBackend as CommunicationBackend>::Receiver,
            _communication: &TestCommunicationBackend,
            _sessions: &TestSessionRepository,
        ) -> Result<IncomingMessage, Self::ReceiveError> {
            match &self.receive_result {
                Some(result) => result.clone(),
                None => {
                    // Simulate waiting for a message but never returning
                    sleep(Duration::from_secs(600)).await;
                    Err("Simulated timeout".to_string())
                }
            }
        }

        async fn send(
            &self,
            _communication: &TestCommunicationBackend,
            _sessions: &TestSessionRepository,
            _message: OutgoingMessage,
        ) -> Result<(), Self::SendError> {
            match &self.send_result {
                Some(result) => result.clone(),
                None => {
                    // Simulate waiting for a message to be send but never returning
                    sleep(Duration::from_secs(600)).await;
                    Err("Simulated timeout".to_string())
                }
            }
        }
    }

    #[tokio::test]
    async fn returns_send_error_when_crypto_provider_returns_error() {
        let message = OutgoingMessage {
            payload: vec![],
            destination: Endpoint::BrowserBackground,
            topic: None,
        };
        let crypto_provider = TestCryptoProvider {
            send_result: Some(Err("Crypto error".to_string())),
            receive_result: Some(Err("Should not have be called".to_string())),
        };
        let communication_provider = TestCommunicationBackend::new();
        let session_map = TestSessionRepository::new(HashMap::new());
        let client = IpcClient::new(crypto_provider, communication_provider, session_map);
        client.start().await;

        let error = client.send(message).await.unwrap_err();

        assert_eq!(error, "Crypto error".to_string());
    }

    #[tokio::test]
    async fn communication_provider_has_outgoing_message_when_sending_through_ipc_client() {
        let message = OutgoingMessage {
            payload: vec![],
            destination: Endpoint::BrowserBackground,
            topic: None,
        };
        let crypto_provider = NoEncryptionCryptoProvider;
        let communication_provider = TestCommunicationBackend::new();
        let session_map = InMemorySessionRepository::new(HashMap::new());
        let client = IpcClient::new(crypto_provider, communication_provider.clone(), session_map);
        client.start().await;

        client.send(message.clone()).await.unwrap();

        let outgoing_messages = communication_provider.outgoing().await;
        assert_eq!(outgoing_messages, vec![message]);
    }

    #[tokio::test]
    async fn returns_received_message_when_received_from_backend() {
        let message = IncomingMessage {
            payload: vec![],
            source: Endpoint::Web { id: 9001 },
            destination: Endpoint::BrowserBackground,
            topic: None,
        };
        let crypto_provider = NoEncryptionCryptoProvider;
        let communication_provider = TestCommunicationBackend::new();
        let session_map = InMemorySessionRepository::new(HashMap::new());
        let client = IpcClient::new(crypto_provider, communication_provider.clone(), session_map);
        client.start().await;

        let mut subscription = client
            .subscribe(None)
            .await
            .expect("Subscribing should not fail");
        communication_provider.push_incoming(message.clone());
        let received_message = subscription.receive(None).await.unwrap();

        assert_eq!(received_message, message);
    }

    #[tokio::test]
    async fn skips_non_matching_topics_and_returns_first_matching_message() {
        let non_matching_message = IncomingMessage {
            payload: vec![],
            source: Endpoint::Web { id: 9001 },
            destination: Endpoint::BrowserBackground,
            topic: Some("non_matching_topic".to_owned()),
        };
        let matching_message = IncomingMessage {
            payload: vec![109],
            source: Endpoint::Web { id: 9001 },
            destination: Endpoint::BrowserBackground,
            topic: Some("matching_topic".to_owned()),
        };

        let crypto_provider = NoEncryptionCryptoProvider;
        let communication_provider = TestCommunicationBackend::new();
        let session_map = InMemorySessionRepository::new(HashMap::new());
        let client = IpcClient::new(crypto_provider, communication_provider.clone(), session_map);
        client.start().await;
        let mut subscription = client
            .subscribe(Some("matching_topic".to_owned()))
            .await
            .expect("Subscribing should not fail");
        communication_provider.push_incoming(non_matching_message.clone());
        communication_provider.push_incoming(non_matching_message.clone());
        communication_provider.push_incoming(matching_message.clone());

        let received_message: IncomingMessage = subscription.receive(None).await.unwrap();

        assert_eq!(received_message, matching_message);
    }

    #[tokio::test]
    async fn skips_unrelated_messages_and_returns_typed_message() {
        #[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
        struct TestPayload {
            some_data: String,
        }

        impl PayloadTypeName for TestPayload {
            fn name() -> String {
                "TestPayload".to_string()
            }
        }

        impl TryFrom<Vec<u8>> for TestPayload {
            type Error = serde_json::Error;

            fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
                serde_json::from_slice(&value)
            }
        }

        impl TryFrom<TestPayload> for Vec<u8> {
            type Error = serde_json::Error;

            fn try_from(value: TestPayload) -> Result<Self, Self::Error> {
                serde_json::to_vec(&value)
            }
        }

        let unrelated = IncomingMessage {
            payload: vec![],
            source: Endpoint::Web { id: 9001 },
            destination: Endpoint::BrowserBackground,
            topic: None,
        };
        let typed_message = TypedIncomingMessage {
            payload: TestPayload {
                some_data: "Hello, world!".to_string(),
            },
            source: Endpoint::Web { id: 9001 },
            destination: Endpoint::BrowserBackground,
        };

        let crypto_provider = NoEncryptionCryptoProvider;
        let communication_provider = TestCommunicationBackend::new();
        let session_map = InMemorySessionRepository::new(HashMap::new());
        let client = IpcClient::new(crypto_provider, communication_provider.clone(), session_map);
        client.start().await;
        let mut subscription = client
            .subscribe_typed::<TestPayload>()
            .await
            .expect("Subscribing should not fail");
        communication_provider.push_incoming(unrelated.clone());
        communication_provider.push_incoming(unrelated.clone());
        communication_provider.push_incoming(
            typed_message
                .clone()
                .try_into()
                .expect("Serialization should not fail"),
        );

        let received_message = subscription.receive(None).await.unwrap();

        assert_eq!(received_message, typed_message);
    }

    #[tokio::test]
    async fn returns_error_if_related_message_was_not_deserializable() {
        #[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
        struct TestPayload {
            some_data: String,
        }

        impl PayloadTypeName for TestPayload {
            fn name() -> String {
                "TestPayload".to_string()
            }
        }

        impl TryFrom<Vec<u8>> for TestPayload {
            type Error = serde_json::Error;

            fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
                serde_json::from_slice(&value)
            }
        }

        impl TryFrom<TestPayload> for Vec<u8> {
            type Error = serde_json::Error;

            fn try_from(value: TestPayload) -> Result<Self, Self::Error> {
                serde_json::to_vec(&value)
            }
        }

        let non_deserializable_message = IncomingMessage {
            payload: vec![],
            source: Endpoint::Web { id: 9001 },
            destination: Endpoint::BrowserBackground,
            topic: Some("TestPayload".to_owned()),
        };

        let crypto_provider = NoEncryptionCryptoProvider;
        let communication_provider = TestCommunicationBackend::new();
        let session_map = InMemorySessionRepository::new(HashMap::new());
        let client = IpcClient::new(crypto_provider, communication_provider.clone(), session_map);
        client.start().await;
        let mut subscription = client
            .subscribe_typed::<TestPayload>()
            .await
            .expect("Subscribing should not fail");
        communication_provider.push_incoming(non_deserializable_message.clone());

        let result = subscription.receive(None).await;
        assert!(matches!(result, Err(TypedReceiveError::Typing(_))));
    }

    #[tokio::test]
    async fn ipc_client_stops_if_crypto_returns_send_error() {
        let message = OutgoingMessage {
            payload: vec![],
            destination: Endpoint::BrowserBackground,
            topic: None,
        };
        let crypto_provider = TestCryptoProvider {
            send_result: Some(Err("Crypto error".to_string())),
            receive_result: None,
        };
        let communication_provider = TestCommunicationBackend::new();
        let session_map = TestSessionRepository::new(HashMap::new());
        let client = IpcClient::new(crypto_provider, communication_provider, session_map);
        client.start().await;

        let error = client.send(message).await.unwrap_err();
        let is_running = client.is_running().await;

        assert_eq!(error, "Crypto error".to_string());
        assert!(!is_running);
    }

    #[tokio::test]
    async fn ipc_client_stops_if_crypto_returns_receive_error() {
        let crypto_provider = TestCryptoProvider {
            send_result: None,
            receive_result: Some(Err("Crypto error".to_string())),
        };
        let communication_provider = TestCommunicationBackend::new();
        let session_map = TestSessionRepository::new(HashMap::new());
        let client = IpcClient::new(crypto_provider, communication_provider, session_map);
        client.start().await;

        // Give the client some time to process the error
        tokio::time::sleep(Duration::from_millis(100)).await;
        let is_running = client.is_running().await;

        assert!(!is_running);
    }

    #[tokio::test]
    async fn ipc_client_is_running_if_no_errors_are_encountered() {
        let crypto_provider = TestCryptoProvider {
            send_result: None,
            receive_result: None,
        };
        let communication_provider = TestCommunicationBackend::new();
        let session_map = TestSessionRepository::new(HashMap::new());
        let client = IpcClient::new(crypto_provider, communication_provider, session_map);
        client.start().await;

        // Give the client some time to process
        tokio::time::sleep(Duration::from_millis(100)).await;
        let is_running = client.is_running().await;

        assert!(is_running);
    }
}

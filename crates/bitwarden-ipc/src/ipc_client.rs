use std::{sync::Arc, time::Duration};

use bitwarden_error::bitwarden_error;
use thiserror::Error;
use tokio::{select, sync::RwLock};

use crate::{
    constants::CHANNEL_BUFFER_CAPACITY,
    endpoint::Endpoint,
    message::{
        IncomingMessage, OutgoingMessage, PayloadTypeName, TypedIncomingMessage,
        TypedOutgoingMessage,
    },
    rpc::{
        error::RpcError, handler_registry::RpcHandlerRegistry, request::RpcRequest,
        request_message::RpcRequestMessage, response_message::RpcResponseMessage,
    },
    traits::{CommunicationBackend, CryptoProvider, SessionRepository},
    RpcHandler,
};

pub struct IpcClient<Crypto, Com, Ses>
where
    Crypto: CryptoProvider<Com, Ses>,
    Com: CommunicationBackend,
    Ses: SessionRepository<Crypto::Session>,
{
    crypto: Crypto,
    communication: Com,
    sessions: Ses,

    handlers: RpcHandlerRegistry,
    incoming: RwLock<Option<tokio::sync::broadcast::Receiver<IncomingMessage>>>,
    cancellation_handle: RwLock<Option<tokio::sync::watch::Sender<bool>>>,
}

/// A subscription to receive messages over IPC.
/// The subcription will start buffering messages after its creation and return them
/// when receive() is called. Messages received before the subscription was created will not be
/// returned.
pub struct IpcClientSubscription<Crypto, Com, Ses>
where
    Crypto: CryptoProvider<Com, Ses>,
    Com: CommunicationBackend,
    Ses: SessionRepository<Crypto::Session>,
{
    receiver: tokio::sync::broadcast::Receiver<IncomingMessage>,
    client: Arc<IpcClient<Crypto, Com, Ses>>,
    topic: Option<String>,
}

/// A subscription to receive messages over IPC.
/// The subcription will start buffering messages after its creation and return them
/// when receive() is called. Messages received before the subscription was created will not be
/// returned.
pub struct IpcClientTypedSubscription<Crypto, Com, Ses, Payload>
where
    Crypto: CryptoProvider<Com, Ses>,
    Com: CommunicationBackend,
    Ses: SessionRepository<Crypto::Session>,
    Payload: TryFrom<Vec<u8>> + PayloadTypeName,
{
    receiver: tokio::sync::broadcast::Receiver<IncomingMessage>,
    client: Arc<IpcClient<Crypto, Com, Ses>>,
    _payload: std::marker::PhantomData<Payload>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[bitwarden_error(flat)]
pub enum SubscribeError {
    #[error("The IPC processing thread is not running")]
    NotStarted,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[bitwarden_error(basic)]
#[error("Failed to start the IPC client: {0}")]
pub struct StartError(String);

#[derive(Debug, Error, PartialEq, Eq)]
#[bitwarden_error(flat)]
pub enum ReceiveError {
    #[error("Failed to subscribe to the IPC channel: {0}")]
    Channel(#[from] tokio::sync::broadcast::error::RecvError),

    #[error("Timed out while waiting for a message: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),
}

#[derive(Debug, Error, PartialEq, Eq)]
#[bitwarden_error(flat)]
pub enum TypedReceiveError {
    #[error("Failed to subscribe to the IPC channel: {0}")]
    Channel(#[from] tokio::sync::broadcast::error::RecvError),

    #[error("Timed out while waiting for a message: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),

    #[error("Typing error: {0}")]
    Typing(String),
}

impl From<ReceiveError> for TypedReceiveError {
    fn from(value: ReceiveError) -> Self {
        match value {
            ReceiveError::Channel(e) => TypedReceiveError::Channel(e),
            ReceiveError::Timeout(e) => TypedReceiveError::Timeout(e),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RequestError<SendError> {
    #[error(transparent)]
    Subscribe(#[from] SubscribeError),

    #[error(transparent)]
    Receive(#[from] TypedReceiveError),

    #[error("Timed out while waiting for a message: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),

    #[error("Failed to send message: {0}")]
    Send(SendError),

    #[error("Error occured on the remote target: {0}")]
    RpcError(#[from] RpcError),
}

impl<Crypto, Com, Ses> IpcClient<Crypto, Com, Ses>
where
    Crypto: CryptoProvider<Com, Ses>,
    Com: CommunicationBackend,
    Ses: SessionRepository<Crypto::Session>,
{
    pub fn new(crypto: Crypto, communication: Com, sessions: Ses) -> Arc<Self> {
        Arc::new(Self {
            crypto,
            communication,
            sessions,

            handlers: RpcHandlerRegistry::new(),
            incoming: RwLock::new(None),
            cancellation_handle: RwLock::new(None),
        })
    }

    pub async fn start(self: &Arc<Self>) -> Result<(), StartError> {
        let client = self.clone();
        let (cancellation_handle_tx, mut cancellation_handle_rx) =
            tokio::sync::watch::channel(false);
        let (await_init_tx, await_init_rx) = tokio::sync::oneshot::channel();
        let mut cancellation_handle = self.cancellation_handle.write().await;

        *cancellation_handle = Some(cancellation_handle_tx);

        let future = async move {
            let com_receiver = client.communication.subscribe().await;
            let (client_tx, client_rx) = tokio::sync::broadcast::channel(CHANNEL_BUFFER_CAPACITY);

            let mut client_incoming = client.incoming.write().await;
            *client_incoming = Some(client_rx);
            drop(client_incoming);

            await_init_tx
                .send(())
                .expect("Sending init signal should not fail");

            loop {
                let rpc_topic = RpcRequestMessage::name();
                select! {
                    _ = cancellation_handle_rx.changed() => {
                        if *cancellation_handle_rx.borrow() {
                            log::debug!("Cancellation signal received, stopping IPC client");
                            break;
                        }
                    }
                    received = client.crypto.receive(&com_receiver, &client.communication, &client.sessions) => {
                        match received {
                            Ok(message) if message.topic == Some(rpc_topic) => {
                                client.handle_rpc_request(message)
                            }
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

        await_init_rx.await.map_err(|e| StartError(e.to_string()))?;
        Ok(())
    }

    pub async fn is_running(self: &Arc<Self>) -> bool {
        let incoming = self.incoming.read().await;
        let cancellation_handle = self.cancellation_handle.read().await;
        incoming.is_some() && cancellation_handle.is_some()
    }

    pub async fn stop(self: &Arc<Self>) {
        let mut incoming = self.incoming.write().await;
        if let Some(receiver) = incoming.take() {
            drop(receiver);
        }

        let mut cancellation_handle = self.cancellation_handle.write().await;
        if let Some(cancellation_rx) = cancellation_handle.take() {
            let _ = cancellation_rx.send(true);
        }
    }

    pub async fn register_rpc_handler<H>(self: &Arc<Self>, handler: H)
    where
        H: RpcHandler + Send + Sync + 'static,
        H::Request: RpcRequest + TryFrom<Vec<u8>> + TryInto<Vec<u8>>,
        <H::Request as RpcRequest>::Response: TryFrom<Vec<u8>> + TryInto<Vec<u8>>,
        <H::Request as TryFrom<Vec<u8>>>::Error: std::fmt::Display,
        <H::Request as TryInto<Vec<u8>>>::Error: std::fmt::Display,
        <<H::Request as RpcRequest>::Response as TryFrom<Vec<u8>>>::Error: std::fmt::Display,
        <<H::Request as RpcRequest>::Response as TryInto<Vec<u8>>>::Error: std::fmt::Display,
    {
        println!("Registering handler for {}", H::Request::name());
        self.handlers.register(handler).await;
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
    ) -> Result<IpcClientSubscription<Crypto, Com, Ses>, SubscribeError> {
        Ok(IpcClientSubscription {
            receiver: self
                .incoming
                .read()
                .await
                .as_ref()
                .ok_or(SubscribeError::NotStarted)?
                .resubscribe(),
            client: self.clone(),
            topic,
        })
    }

    /// Create a subscription to receive messages that can be deserialized into the provided payload
    /// type.
    pub async fn subscribe_typed<Payload>(
        self: &Arc<Self>,
    ) -> Result<IpcClientTypedSubscription<Crypto, Com, Ses, Payload>, SubscribeError>
    where
        Payload: TryFrom<Vec<u8>> + PayloadTypeName,
    {
        Ok(IpcClientTypedSubscription {
            receiver: self
                .incoming
                .read()
                .await
                .as_ref()
                .ok_or(SubscribeError::NotStarted)?
                .resubscribe(),
            client: self.clone(),
            _payload: std::marker::PhantomData,
        })
    }

    async fn receive(
        &self,
        receiver: &mut tokio::sync::broadcast::Receiver<IncomingMessage>,
        topic: &Option<String>,
        timeout: Option<Duration>,
    ) -> Result<IncomingMessage, ReceiveError> {
        let receive_loop = async {
            loop {
                let received = receiver.recv().await?;
                if topic.is_none() || &received.topic == topic {
                    return Ok::<IncomingMessage, ReceiveError>(received);
                }
            }
        };

        Ok(if let Some(timeout) = timeout {
            tokio::time::timeout(timeout, receive_loop).await??
        } else {
            receive_loop.await?
        })
    }

    pub async fn request<Request>(
        self: &Arc<Self>,
        request: Request,
        destination: Endpoint,
        timeout: Option<Duration>,
    ) -> Result<Request::Response, RequestError<Crypto::SendError>>
    where
        Request: RpcRequest + TryInto<Vec<u8>> + TryFrom<Vec<u8>>,
        Request::Response: TryInto<Vec<u8>> + TryFrom<Vec<u8>>,
        <Request as TryInto<Vec<u8>>>::Error: std::fmt::Display,
        <Request::Response as TryFrom<Vec<u8>>>::Error: std::fmt::Display,
    {
        let request_id = uuid::Uuid::new_v4().to_string();
        let mut response_subscription: IpcClientTypedSubscription<_, _, _, RpcResponseMessage> =
            self.subscribe_typed().await?;

        let request_payload = RpcRequestMessage {
            request: request
                .try_into()
                .map_err(|e| RpcError::RequestSerializationError(e.to_string()))?,
            request_id: request_id.clone(),
            request_type: Request::name(),
        };

        let message = TypedOutgoingMessage {
            payload: request_payload,
            destination,
        }
        .try_into()
        .map_err(
            |e: <TypedOutgoingMessage<RpcRequestMessage> as TryInto<OutgoingMessage>>::Error| {
                RequestError::<Crypto::SendError>::RpcError(RpcError::RequestSerializationError(
                    e.to_string(),
                ))
            },
        )?;

        self.send(message)
            .await
            .map_err(|e| RequestError::<Crypto::SendError>::Send(e))?;

        let receive_loop = async {
            loop {
                let received = response_subscription
                    .receive(timeout)
                    .await
                    .map_err(|e| RequestError::<Crypto::SendError>::Receive(e.into()));

                match received {
                    Ok(response) => {
                        if response.payload.request_id == request_id {
                            return Ok(response);
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
        };

        let response: TypedIncomingMessage<RpcResponseMessage> = if let Some(timeout) = timeout {
            tokio::time::timeout(timeout, receive_loop).await??
        } else {
            receive_loop.await?
        };

        let result: Request::Response = response.payload.result?.try_into().map_err(
            |e: <Request::Response as TryFrom<Vec<u8>>>::Error| {
                RequestError::<Crypto::SendError>::RpcError(RpcError::ResponseDeserializationError(
                    e.to_string(),
                ))
            },
        )?;

        Ok(result)
    }

    #[allow(dead_code)]
    fn handle_rpc_request(self: &Arc<Self>, incoming_message: IncomingMessage) {
        let client = self.clone();
        let future = async move {
            let client = client.clone();

            #[derive(Debug, Error)]
            enum HandleError {
                #[error("Failed to deserialize request message: {0}")]
                Deserialize(String),

                #[error("Failed to serialize response message: {0}")]
                Serialize(String),
            }

            async fn handle(
                incoming_message: IncomingMessage,
                handlers: &RpcHandlerRegistry,
            ) -> Result<OutgoingMessage, HandleError> {
                let request: RpcRequestMessage = incoming_message.payload.try_into().map_err(
                    |e: <RpcRequestMessage as TryFrom<Vec<u8>>>::Error| {
                        HandleError::Deserialize(e.to_string())
                    },
                )?;

                let response = handlers
                    .handle(&request.request_type, request.request)
                    .await;

                let response_message = RpcResponseMessage {
                    request_id: request.request_id,
                    request_type: request.request_type,
                    result: response,
                };

                let outgoing = TypedOutgoingMessage {
                    payload: response_message,
                    destination: incoming_message.source,
                }
                .try_into()
                .map_err(
                    |e: <TypedOutgoingMessage<RpcResponseMessage> as TryInto<
                        OutgoingMessage,
                    >>::Error| { HandleError::Serialize(e.to_string()) },
                )?;

                Ok(outgoing)
            }

            match handle(incoming_message, &client.handlers).await {
                Ok(outgoing_message) => {
                    if client.send(outgoing_message).await.is_err() {
                        log::error!("Failed to send response message");
                    }
                }
                Err(e) => {
                    log::error!("Error handling RPC request: {:?}", e);
                }
            }
        };

        #[cfg(not(target_arch = "wasm32"))]
        tokio::spawn(future);

        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(future);
    }
}

impl<Crypto, Com, Ses> IpcClientSubscription<Crypto, Com, Ses>
where
    Crypto: CryptoProvider<Com, Ses>,
    Com: CommunicationBackend,
    Ses: SessionRepository<Crypto::Session>,
{
    /// Receive a message, optionally filtering by topic.
    /// Setting the timeout to `None` will wait indefinitely.
    pub async fn receive(
        &mut self,
        timeout: Option<Duration>,
    ) -> Result<IncomingMessage, ReceiveError> {
        self.client
            .receive(&mut self.receiver, &self.topic, timeout)
            .await
    }
}

impl<Crypto, Com, Ses, Payload, TryFromError> IpcClientTypedSubscription<Crypto, Com, Ses, Payload>
where
    Crypto: CryptoProvider<Com, Ses>,
    Com: CommunicationBackend,
    Ses: SessionRepository<Crypto::Session>,
    Payload: TryFrom<Vec<u8>, Error = TryFromError> + PayloadTypeName,
    TryFromError: std::fmt::Display,
{
    /// Receive a message.
    /// Setting the timeout to `None` will wait indefinitely.
    pub async fn receive(
        &mut self,
        timeout: Option<Duration>,
    ) -> Result<TypedIncomingMessage<Payload>, TypedReceiveError> {
        let topic = Some(Payload::name());
        let received = self
            .client
            .receive(&mut self.receiver, &topic, timeout)
            .await?;
        received
            .try_into()
            .map_err(|e: TryFromError| TypedReceiveError::Typing(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

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
                    tokio::time::sleep(Duration::from_secs(600)).await;
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
                    tokio::time::sleep(Duration::from_secs(600)).await;
                    Err("Simulated timeout".to_string())
                }
            }
        }
    }

    #[tokio::test]
    async fn returns_send_error_when_crypto_provider_returns_error() {
        // TODO: THIS LOCKS UP!
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
        client
            .start()
            .await
            .expect("Starting client should not fail");

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
        client
            .start()
            .await
            .expect("Starting client should not fail");

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
        client
            .start()
            .await
            .expect("Starting client should not fail");

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
        client
            .start()
            .await
            .expect("Starting client should not fail");
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
        client
            .start()
            .await
            .expect("Starting client should not fail");
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
    // async fn skips_message_if_it_was_not_deserializable() {
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
        client
            .start()
            .await
            .expect("Starting client should not fail");
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
        client
            .start()
            .await
            .expect("Starting client should not fail");

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
        client
            .start()
            .await
            .expect("Starting client should not fail");

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
        client
            .start()
            .await
            .expect("Starting client should not fail");

        // Give the client some time to process
        tokio::time::sleep(Duration::from_millis(100)).await;
        let is_running = client.is_running().await;

        assert!(is_running);
    }

    mod request {
        use crate::rpc::{
            request_message::RpcRequestMessage, response_message::RpcResponseMessage,
        };

        use super::*;

        #[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
        struct TestRequest {
            a: i32,
            b: i32,
        }

        #[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
        struct TestResponse {
            result: i32,
        }

        impl RpcRequest for TestRequest {
            type Response = TestResponse;

            fn name() -> String {
                "TestRequest".to_string()
            }
        }

        impl TryFrom<TestRequest> for Vec<u8> {
            type Error = serde_json::Error;

            fn try_from(value: TestRequest) -> Result<Self, Self::Error> {
                serde_json::to_vec(&value)
            }
        }

        impl TryFrom<Vec<u8>> for TestRequest {
            type Error = serde_json::Error;

            fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
                serde_json::from_slice(&value)
            }
        }

        impl TryFrom<TestResponse> for Vec<u8> {
            type Error = serde_json::Error;

            fn try_from(value: TestResponse) -> Result<Self, Self::Error> {
                serde_json::to_vec(&value)
            }
        }

        impl TryFrom<Vec<u8>> for TestResponse {
            type Error = serde_json::Error;

            fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
                serde_json::from_slice(&value)
            }
        }

        struct TestHandler;

        impl RpcHandler for TestHandler {
            type Request = TestRequest;

            async fn handle(&self, request: Self::Request) -> TestResponse {
                TestResponse {
                    result: request.a + request.b,
                }
            }
        }

        #[tokio::test]
        async fn request_sends_message_and_returns_response() {
            let crypto_provider = NoEncryptionCryptoProvider;
            let communication_provider = TestCommunicationBackend::new();
            let session_map = InMemorySessionRepository::new(HashMap::new());
            let client =
                IpcClient::new(crypto_provider, communication_provider.clone(), session_map);
            client
                .start()
                .await
                .expect("Starting client should not fail");
            let request = TestRequest { a: 1, b: 2 };
            let response = TestResponse { result: 3 };

            // Send the request
            let request_clone = request.clone();
            let result_handle = tokio::spawn(async move {
                let client = client.clone();
                client
                    .request::<TestRequest>(
                        request_clone,
                        Endpoint::BrowserBackground,
                        Some(Duration::from_secs(1)),
                    )
                    .await
            });
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Read and verify the outgoing message
            let outgoing_messages = communication_provider.outgoing().await;
            let outgoing_request: RpcRequestMessage = outgoing_messages[0]
                .clone()
                .payload
                .try_into()
                .expect("Deserialization should not fail");
            assert_eq!(outgoing_request.request_type, "TestRequest");
            let sent_request: TestRequest = outgoing_request.request.try_into().unwrap();
            assert_eq!(sent_request, request);

            // Simulate receiving a response
            let simulated_response = RpcResponseMessage {
                result: Ok(response.try_into().unwrap()),
                request_id: outgoing_request.request_id.clone(),
                request_type: outgoing_request.request_type.clone(),
            };
            let simulated_response = IncomingMessage {
                payload: simulated_response
                    .try_into()
                    .expect("Serialization should not fail"),
                source: Endpoint::BrowserBackground,
                destination: Endpoint::Web { id: 9001 },
                topic: Some(RpcResponseMessage::name()),
            };
            communication_provider.push_incoming(
                simulated_response
                    .try_into()
                    .expect("Serialization should not fail"),
            );

            // Wait for the response
            let result = result_handle.await.unwrap();
            assert_eq!(result.unwrap().result, 3);
        }

        #[tokio::test]
        async fn incoming_rpc_message_handles_request_and_returns_response() {
            let crypto_provider = NoEncryptionCryptoProvider;
            let communication_provider = TestCommunicationBackend::new();
            let session_map = InMemorySessionRepository::new(HashMap::new());
            let client =
                IpcClient::new(crypto_provider, communication_provider.clone(), session_map);
            client
                .start()
                .await
                .expect("Starting client should not fail");
            let request_id = uuid::Uuid::new_v4().to_string();
            let request = TestRequest { a: 1, b: 2 };
            let response = TestResponse { result: 3 };

            // Register the handler
            client.register_rpc_handler(TestHandler).await;

            // Simulate receiving a request
            let simulated_request = RpcRequestMessage {
                request: request.try_into().unwrap(),
                request_id: request_id.clone(),
                request_type: "TestRequest".to_string(),
            };
            let simulated_request_message = IncomingMessage {
                payload: simulated_request
                    .try_into()
                    .expect("Serialization should not fail"),
                source: Endpoint::Web { id: 9001 },
                destination: Endpoint::BrowserBackground,
                topic: Some(RpcRequestMessage::name()),
            };
            communication_provider.push_incoming(
                simulated_request_message
                    .try_into()
                    .expect("Serialization should not fail"),
            );

            // Give the client some time to process the request
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Read and verify the outgoing message
            let outgoing_messages = communication_provider.outgoing().await;
            let outgoing_response: RpcResponseMessage = outgoing_messages[0]
                .clone()
                .payload
                .try_into()
                .expect("Deserialization should not fail");
            let result: TestResponse = outgoing_response.result.unwrap().try_into().unwrap();

            assert_eq!(outgoing_messages[0].topic, Some(RpcResponseMessage::name()));
            assert_eq!(outgoing_response.request_type, "TestRequest");
            assert_eq!(result, response);
        }
    }
}

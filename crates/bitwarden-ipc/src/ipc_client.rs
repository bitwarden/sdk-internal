use std::sync::Arc;

use bitwarden_error::bitwarden_error;
use bitwarden_threading::cancellation_token::CancellationToken;
use serde::de::DeserializeOwned;
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
        error::RpcError,
        exec::handler_registry::RpcHandlerRegistry,
        request::RpcRequest,
        request_message::{RpcRequestMessage, RpcRequestPayload, RPC_REQUEST_PAYLOAD_TYPE_NAME},
        response_message::{IncomingRpcResponseMessage, OutgoingRpcResponseMessage},
    },
    serde_utils,
    traits::{CommunicationBackend, CryptoProvider, SessionRepository},
    RpcHandler,
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

    handlers: RpcHandlerRegistry,
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
pub struct IpcClientTypedSubscription<Payload: DeserializeOwned + PayloadTypeName>(
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

#[derive(Debug, Error, PartialEq, Eq)]
#[bitwarden_error(flat)]
#[allow(missing_docs)]
pub enum RequestError {
    #[error(transparent)]
    Subscribe(#[from] SubscribeError),

    #[error(transparent)]
    Receive(#[from] TypedReceiveError),

    #[error("Timed out while waiting for a message: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),

    #[error("Failed to send message: {0}")]
    Send(String),

    #[error("Error occured on the remote target: {0}")]
    RpcError(#[from] RpcError),
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

            handlers: RpcHandlerRegistry::new(),
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
                let rpc_topic = RPC_REQUEST_PAYLOAD_TYPE_NAME.to_owned();
                select! {
                    _ = cancellation_token.cancelled() => {
                        log::debug!("Cancellation signal received, stopping IPC client");
                        break;
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
                                log::error!("Error receiving message: {e:?}");
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

    /// Register a new RPC handler for processing incoming RPC requests.
    /// The handler will be executed by the IPC client when an RPC request is received and
    /// the response will be sent back over IPC.
    pub async fn register_rpc_handler<H>(self: &Arc<Self>, handler: H)
    where
        H: RpcHandler + Send + Sync + 'static,
    {
        self.handlers.register(handler).await;
    }

    /// Send a message
    pub async fn send(self: &Arc<Self>, message: OutgoingMessage) -> Result<(), Crypto::SendError> {
        let result = self
            .crypto
            .send(&self.communication, &self.sessions, message)
            .await;

        if result.is_err() {
            log::error!("Error sending message: {result:?}");
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
        Payload: DeserializeOwned + PayloadTypeName,
    {
        Ok(IpcClientTypedSubscription(
            self.subscribe(Some(Payload::PAYLOAD_TYPE_NAME.to_owned()))
                .await?,
            std::marker::PhantomData,
        ))
    }

    /// Send a request to the specified destination and wait for a response.
    /// The destination must have a registered RPC handler for the request type, otherwise
    /// an error will be returned by the remote endpoint.
    pub async fn request<Request>(
        self: &Arc<Self>,
        request: Request,
        destination: Endpoint,
        cancellation_token: Option<CancellationToken>,
    ) -> Result<Request::Response, RequestError>
    where
        Request: RpcRequest,
    {
        let request_id = uuid::Uuid::new_v4().to_string();
        let mut response_subscription = self
            .subscribe_typed::<IncomingRpcResponseMessage<_>>()
            .await?;

        let request_payload = RpcRequestMessage {
            request,
            request_id: request_id.clone(),
            request_type: Request::NAME.to_owned(),
        };

        let message = TypedOutgoingMessage {
            payload: request_payload,
            destination,
        }
        .try_into()
        .map_err(|e: serde_utils::DeserializeError| {
            RequestError::RpcError(RpcError::RequestSerializationError(e.to_string()))
        })?;

        self.send(message)
            .await
            .map_err(|e| RequestError::Send(format!("{e:?}")))?;

        let response = loop {
            let received = response_subscription
                .receive(cancellation_token.clone())
                .await
                .map_err(RequestError::Receive)?;

            if received.payload.request_id == request_id {
                break received;
            }
        };

        Ok(response.payload.result?)
    }

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
                let request = RpcRequestPayload::from_slice(incoming_message.payload.clone())
                    .map_err(|e: serde_utils::DeserializeError| {
                        HandleError::Deserialize(e.to_string())
                    })?;

                let response = handlers.handle(&request).await;

                let response_message = OutgoingRpcResponseMessage {
                    request_id: request.request_id(),
                    request_type: request.request_type(),
                    result: response,
                };

                let outgoing = TypedOutgoingMessage {
                    payload: response_message,
                    destination: incoming_message.source,
                }
                .try_into()
                .map_err(|e: serde_utils::SerializeError| HandleError::Serialize(e.to_string()))?;

                Ok(outgoing)
            }

            match handle(incoming_message, &client.handlers).await {
                Ok(outgoing_message) => {
                    if client.send(outgoing_message).await.is_err() {
                        log::error!("Failed to send response message");
                    }
                }
                Err(e) => {
                    log::error!("Error handling RPC request: {e:?}");
                }
            }
        };

        #[cfg(not(target_arch = "wasm32"))]
        tokio::spawn(future);

        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(future);
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

impl<Payload> IpcClientTypedSubscription<Payload>
where
    Payload: DeserializeOwned + PayloadTypeName,
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
            .map_err(|e: serde_utils::DeserializeError| TypedReceiveError::Typing(e.to_string()))
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
            const PAYLOAD_TYPE_NAME: &str = "TestPayload";
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
            const PAYLOAD_TYPE_NAME: &str = "TestPayload";
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

    mod request {
        use super::*;
        use crate::rpc::response_message::IncomingRpcResponseMessage;

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

            const NAME: &str = "TestRequest";
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
            client.start().await;
            let request = TestRequest { a: 1, b: 2 };
            let response = TestResponse { result: 3 };

            // Send the request
            let request_clone = request.clone();
            let result_handle = tokio::spawn(async move {
                let client = client.clone();
                client
                    .request::<TestRequest>(request_clone, Endpoint::BrowserBackground, None)
                    .await
            });
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Read and verify the outgoing message
            let outgoing_messages = communication_provider.outgoing().await;
            let outgoing_request: RpcRequestMessage<TestRequest> =
                serde_utils::from_slice(&outgoing_messages[0].payload)
                    .expect("Deserialization should not fail");
            assert_eq!(outgoing_request.request_type, "TestRequest");
            assert_eq!(outgoing_request.request, request);

            // Simulate receiving a response
            let simulated_response = IncomingRpcResponseMessage {
                result: Ok(response),
                request_id: outgoing_request.request_id.clone(),
                request_type: outgoing_request.request_type.clone(),
            };
            let simulated_response = IncomingMessage {
                payload: serde_utils::to_vec(&simulated_response)
                    .expect("Serialization should not fail"),
                source: Endpoint::BrowserBackground,
                destination: Endpoint::Web { id: 9001 },
                topic: Some(
                    IncomingRpcResponseMessage::<TestRequest>::PAYLOAD_TYPE_NAME.to_owned(),
                ),
            };
            communication_provider.push_incoming(simulated_response);

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
            client.start().await;
            let request_id = uuid::Uuid::new_v4().to_string();
            let request = TestRequest { a: 1, b: 2 };
            let response = TestResponse { result: 3 };

            // Register the handler
            client.register_rpc_handler(TestHandler).await;

            // Simulate receiving a request
            let simulated_request = RpcRequestMessage {
                request,
                request_id: request_id.clone(),
                request_type: "TestRequest".to_string(),
            };
            let simulated_request_message = IncomingMessage {
                payload: serde_utils::to_vec(&simulated_request)
                    .expect("Serialization should not fail"),
                source: Endpoint::Web { id: 9001 },
                destination: Endpoint::BrowserBackground,
                topic: Some(RPC_REQUEST_PAYLOAD_TYPE_NAME.to_owned()),
            };
            communication_provider.push_incoming(simulated_request_message);

            // Give the client some time to process the request
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Read and verify the outgoing message
            let outgoing_messages = communication_provider.outgoing().await;
            let outgoing_response: IncomingRpcResponseMessage<TestResponse> =
                serde_utils::from_slice(&outgoing_messages[0].payload)
                    .expect("Deserialization should not fail");

            assert_eq!(
                outgoing_messages[0].topic,
                Some(IncomingRpcResponseMessage::<TestResponse>::PAYLOAD_TYPE_NAME.to_owned())
            );
            assert_eq!(outgoing_response.request_type, "TestRequest");
            assert_eq!(outgoing_response.result, Ok(response));
        }
    }
}

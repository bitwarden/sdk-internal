use std::sync::{Arc, Mutex};

use bitwarden_threading::cancellation_token::CancellationToken;
use serde::de::DeserializeOwned;
use thiserror::Error;
use tokio::select;

use crate::{
    constants::CHANNEL_BUFFER_CAPACITY,
    error::{AlreadyRunningError, ReceiveError, SendError, SubscribeError, TypedReceiveError},
    message::{
        IncomingMessage, OutgoingMessage, PayloadTypeName, TypedIncomingMessage,
        TypedOutgoingMessage,
    },
    rpc::{
        exec::{handler::ErasedRpcHandler, handler_registry::RpcHandlerRegistry},
        request_message::{RPC_REQUEST_PAYLOAD_TYPE_NAME, RpcRequestPayload},
        response_message::OutgoingRpcResponseMessage,
    },
    serde_utils,
    traits::{CommunicationBackend, CryptoProvider, SessionRepository},
};

/// A subscription to receive messages over IPC.
/// The subcription will start buffering messages after its creation and return them
/// when receive() is called. Messages received before the subscription was created will not be
/// returned.
pub struct IpcClientSubscription {
    pub(crate) receiver: tokio::sync::broadcast::Receiver<IncomingMessage>,
    pub(crate) topic: Option<String>,
}

/// A subscription to receive messages over IPC.
/// The subcription will start buffering messages after its creation and return them
/// when receive() is called. Messages received before the subscription was created will not be
/// returned.
pub struct IpcClientTypedSubscription<Payload: DeserializeOwned + PayloadTypeName>(
    IpcClientSubscription,
    std::marker::PhantomData<Payload>,
);

/// Internal shared state for the IPC client.
struct IpcClientInner<Crypto, Com, Ses>
where
    Crypto: CryptoProvider<Com, Ses>,
    Com: CommunicationBackend,
    Ses: SessionRepository<Crypto::Session>,
{
    crypto: Crypto,
    communication: Com,
    sessions: Ses,

    handlers: RpcHandlerRegistry,
    incoming: Mutex<Option<tokio::sync::broadcast::Receiver<IncomingMessage>>>,
    cancellation_token: Mutex<Option<CancellationToken>>,
}

/// An IPC client that handles communication between different components and clients.
/// It uses a crypto provider to encrypt and decrypt messages, a communication backend to send and
/// receive messages, and a session repository to persist sessions.
///
/// This is the concrete implementation of the [`IpcClient`](crate::IpcClient) trait.
pub struct IpcClientImpl<Crypto, Com, Ses>
where
    Crypto: CryptoProvider<Com, Ses>,
    Com: CommunicationBackend,
    Ses: SessionRepository<Crypto::Session>,
{
    inner: Arc<IpcClientInner<Crypto, Com, Ses>>,
}

impl<Crypto, Com, Ses> Clone for IpcClientImpl<Crypto, Com, Ses>
where
    Crypto: CryptoProvider<Com, Ses>,
    Com: CommunicationBackend,
    Ses: SessionRepository<Crypto::Session>,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<Crypto, Com, Ses> IpcClientImpl<Crypto, Com, Ses>
where
    Crypto: CryptoProvider<Com, Ses>,
    Com: CommunicationBackend,
    Ses: SessionRepository<Crypto::Session>,
{
    /// Create a new IPC client with the provided crypto provider, communication backend, and
    /// session repository.
    pub fn new(crypto: Crypto, communication: Com, sessions: Ses) -> Self {
        Self {
            inner: Arc::new(IpcClientInner {
                crypto,
                communication,
                sessions,

                handlers: RpcHandlerRegistry::new(),
                incoming: Mutex::new(None),
                cancellation_token: Mutex::new(None),
            }),
        }
    }
}

#[async_trait::async_trait]
impl<Crypto, Com, Ses> crate::ipc_client_trait::IpcClient for IpcClientImpl<Crypto, Com, Ses>
where
    Crypto: CryptoProvider<Com, Ses>,
    Com: CommunicationBackend,
    Ses: SessionRepository<Crypto::Session>,
{
    async fn start(
        &self,
        cancellation_token: Option<CancellationToken>,
    ) -> Result<(), AlreadyRunningError> {
        if self.is_running() {
            return Err(AlreadyRunningError);
        }

        let cancellation_token = cancellation_token.unwrap_or_default();
        self.inner
            .cancellation_token
            .lock()
            .expect("Failed to lock cancellation token mutex")
            .replace(cancellation_token.clone());

        let com_receiver = self.inner.communication.subscribe().await;
        let (client_tx, client_rx) = tokio::sync::broadcast::channel(CHANNEL_BUFFER_CAPACITY);

        self.inner
            .incoming
            .lock()
            .expect("Failed to lock incoming mutex")
            .replace(client_rx);

        let inner = self.inner.clone();
        let future = async move {
            loop {
                let rpc_topic = RPC_REQUEST_PAYLOAD_TYPE_NAME.to_owned();
                select! {
                    _ = cancellation_token.cancelled() => {
                        tracing::debug!("Cancellation signal received, stopping IPC client");
                        break;
                    }
                    received = inner.crypto.receive(&com_receiver, &inner.communication, &inner.sessions) => {
                        match received {
                            Ok(message) if message.topic == Some(rpc_topic) => {
                                handle_rpc_request(&inner, message)
                            }
                            Ok(message) => {
                                if client_tx.send(message).is_err() {
                                    tracing::error!("Failed to save incoming message");
                                    break;
                                };
                            }
                            Err(error) => {
                                tracing::error!(?error, "Error receiving message");
                                break;
                            }
                        }
                    }
                }
            }
            tracing::debug!("IPC client shutting down");
            stop_inner(&inner);
        };

        #[cfg(not(target_arch = "wasm32"))]
        tokio::spawn(future);

        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(future);

        Ok(())
    }

    fn is_running(&self) -> bool {
        let has_incoming = self
            .inner
            .incoming
            .lock()
            .expect("Failed to lock incoming mutex")
            .as_ref()
            .map(|receiver| !receiver.is_closed())
            .unwrap_or(false);
        let has_cancellation_token = self
            .inner
            .cancellation_token
            .lock()
            .expect("Failed to lock cancellation token mutex")
            .is_some();
        has_incoming && has_cancellation_token
    }

    async fn send(&self, message: OutgoingMessage) -> Result<(), SendError> {
        let result = self
            .inner
            .crypto
            .send(&self.inner.communication, &self.inner.sessions, message)
            .await;

        if let Err(ref error) = result {
            tracing::error!(?error, "Error sending message");
            stop_inner(&self.inner);
        }

        result.map_err(|e| SendError(format!("{e:?}")))
    }

    async fn subscribe(
        &self,
        topic: Option<String>,
    ) -> Result<IpcClientSubscription, SubscribeError> {
        Ok(IpcClientSubscription {
            receiver: self
                .inner
                .incoming
                .lock()
                .expect("Failed to lock incoming mutex")
                .as_ref()
                .ok_or(SubscribeError::NotStarted)?
                .resubscribe(),
            topic,
        })
    }

    async fn register_rpc_handler_erased(&self, name: &str, handler: Box<dyn ErasedRpcHandler>) {
        self.inner
            .handlers
            .register_erased(name.to_owned(), handler)
            .await;
    }
}

fn stop_inner<Crypto, Com, Ses>(inner: &IpcClientInner<Crypto, Com, Ses>)
where
    Crypto: CryptoProvider<Com, Ses>,
    Com: CommunicationBackend,
    Ses: SessionRepository<Crypto::Session>,
{
    let mut cancellation_token = inner
        .cancellation_token
        .lock()
        .expect("Failed to lock cancellation token mutex");

    if let Some(cancellation_token) = cancellation_token.take() {
        cancellation_token.cancel();
    }
}

fn handle_rpc_request<Crypto, Com, Ses>(
    inner: &Arc<IpcClientInner<Crypto, Com, Ses>>,
    incoming_message: IncomingMessage,
) where
    Crypto: CryptoProvider<Com, Ses>,
    Com: CommunicationBackend,
    Ses: SessionRepository<Crypto::Session>,
{
    let inner = inner.clone();
    let future = async move {
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
            let request = RpcRequestPayload::from_slice(incoming_message.payload.clone()).map_err(
                |e: serde_utils::DeserializeError| HandleError::Deserialize(e.to_string()),
            )?;

            let response = handlers.handle(&request).await;

            let response_message = OutgoingRpcResponseMessage {
                request_id: request.request_id(),
                request_type: request.request_type(),
                result: response,
            };

            let outgoing = TypedOutgoingMessage {
                payload: response_message,
                destination: incoming_message.source.into(),
            }
            .try_into()
            .map_err(|e: serde_utils::SerializeError| HandleError::Serialize(e.to_string()))?;

            Ok(outgoing)
        }

        match handle(incoming_message, &inner.handlers).await {
            Ok(outgoing_message) => {
                // Send response directly through the crypto provider (not through the trait)
                // since we're inside the background task and don't have a trait object.
                let result = inner
                    .crypto
                    .send(&inner.communication, &inner.sessions, outgoing_message)
                    .await;
                if result.is_err() {
                    tracing::error!("Failed to send response message");
                }
            }
            Err(error) => {
                tracing::error!(%error, "Error handling RPC request");
            }
        }
    };

    #[cfg(not(target_arch = "wasm32"))]
    tokio::spawn(future);

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_futures::spawn_local(future);
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
    pub(crate) fn new(subscription: IpcClientSubscription) -> Self {
        Self(subscription, std::marker::PhantomData)
    }

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
        IpcClientExt,
        endpoint::{Endpoint, HostId, Source},
        ipc_client_trait::IpcClient,
        message::PayloadTypeName,
        rpc::{
            request::RpcRequest,
            request_message::{RPC_REQUEST_PAYLOAD_TYPE_NAME, RpcRequestMessage},
            response_message::IncomingRpcResponseMessage,
        },
        traits::{InMemorySessionRepository, NoEncryptionCryptoProvider, TestCommunicationBackend},
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
            destination: Endpoint::BrowserBackground { id: HostId::Own },
            topic: None,
        };
        let crypto_provider = TestCryptoProvider {
            send_result: Some(Err("Crypto error".to_string())),
            receive_result: Some(Err("Should not have be called".to_string())),
        };
        let communication_provider = TestCommunicationBackend::new();
        let session_map = TestSessionRepository::new(HashMap::new());
        let client = IpcClientImpl::new(crypto_provider, communication_provider, session_map);
        let _ = client.start(None).await;

        let error = client.send(message).await.unwrap_err();

        assert!(error.to_string().contains("Crypto error"));
    }

    #[tokio::test]
    async fn communication_provider_has_outgoing_message_when_sending_through_ipc_client() {
        let message = OutgoingMessage {
            payload: vec![],
            destination: Endpoint::BrowserBackground { id: HostId::Own },
            topic: None,
        };
        let crypto_provider = NoEncryptionCryptoProvider;
        let communication_provider = TestCommunicationBackend::new();
        let session_map = InMemorySessionRepository::new(HashMap::new());
        let client =
            IpcClientImpl::new(crypto_provider, communication_provider.clone(), session_map);
        let _ = client.start(None).await;

        client.send(message.clone()).await.unwrap();

        let outgoing_messages = communication_provider.outgoing().await;
        assert_eq!(outgoing_messages, vec![message]);
    }

    #[tokio::test]
    async fn returns_received_message_when_received_from_backend() {
        let message = IncomingMessage {
            payload: vec![],
            source: Source::Web {
                tab_id: 9001,
                document_id: "doc-1".to_string(),
                origin: "https://example.com".to_string(),
            },
            destination: Endpoint::BrowserBackground { id: HostId::Own },
            topic: None,
        };
        let crypto_provider = NoEncryptionCryptoProvider;
        let communication_provider = TestCommunicationBackend::new();
        let session_map = InMemorySessionRepository::new(HashMap::new());
        let client =
            IpcClientImpl::new(crypto_provider, communication_provider.clone(), session_map);
        let _ = client.start(None).await;

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
            source: Source::Web {
                tab_id: 9001,
                document_id: "doc-1".to_string(),
                origin: "https://example.com".to_string(),
            },
            destination: Endpoint::BrowserBackground { id: HostId::Own },
            topic: Some("non_matching_topic".to_owned()),
        };
        let matching_message = IncomingMessage {
            payload: vec![109],
            source: Source::Web {
                tab_id: 9001,
                document_id: "doc-1".to_string(),
                origin: "https://example.com".to_string(),
            },
            destination: Endpoint::BrowserBackground { id: HostId::Own },
            topic: Some("matching_topic".to_owned()),
        };

        let crypto_provider = NoEncryptionCryptoProvider;
        let communication_provider = TestCommunicationBackend::new();
        let session_map = InMemorySessionRepository::new(HashMap::new());
        let client =
            IpcClientImpl::new(crypto_provider, communication_provider.clone(), session_map);
        let _ = client.start(None).await;
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
            source: Source::Web {
                tab_id: 9001,
                document_id: "doc-1".to_string(),
                origin: "https://example.com".to_string(),
            },
            destination: Endpoint::BrowserBackground { id: HostId::Own },
            topic: None,
        };
        let typed_message = crate::message::TypedIncomingMessage {
            payload: TestPayload {
                some_data: "Hello, world!".to_string(),
            },
            source: Source::Web {
                tab_id: 9001,
                document_id: "doc-1".to_string(),
                origin: "https://example.com".to_string(),
            },
            destination: Endpoint::BrowserBackground { id: HostId::Own },
        };

        let crypto_provider = NoEncryptionCryptoProvider;
        let communication_provider = TestCommunicationBackend::new();
        let session_map = InMemorySessionRepository::new(HashMap::new());
        let client =
            IpcClientImpl::new(crypto_provider, communication_provider.clone(), session_map);
        let _ = client.start(None).await;
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
            source: Source::Web {
                tab_id: 9001,
                document_id: "doc-1".to_string(),
                origin: "https://example.com".to_string(),
            },
            destination: Endpoint::BrowserBackground { id: HostId::Own },
            topic: Some("TestPayload".to_owned()),
        };

        let crypto_provider = NoEncryptionCryptoProvider;
        let communication_provider = TestCommunicationBackend::new();
        let session_map = InMemorySessionRepository::new(HashMap::new());
        let client =
            IpcClientImpl::new(crypto_provider, communication_provider.clone(), session_map);
        let _ = client.start(None).await;
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
            destination: Endpoint::BrowserBackground { id: HostId::Own },
            topic: None,
        };
        let crypto_provider = TestCryptoProvider {
            send_result: Some(Err("Crypto error".to_string())),
            receive_result: None,
        };
        let communication_provider = TestCommunicationBackend::new();
        let session_map = TestSessionRepository::new(HashMap::new());
        let client = IpcClientImpl::new(crypto_provider, communication_provider, session_map);
        let _ = client.start(None).await;

        let error = client.send(message).await.unwrap_err();
        let is_running = client.is_running();

        assert!(error.to_string().contains("Crypto error"));
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
        let client = IpcClientImpl::new(crypto_provider, communication_provider, session_map);
        let cancellation_token = CancellationToken::new();
        let _ = client.start(Some(cancellation_token.clone())).await;

        // Give the client some time to process the error
        tokio::time::sleep(Duration::from_millis(100)).await;
        let is_running = client.is_running();

        assert!(!is_running);
        assert!(cancellation_token.is_cancelled());
    }

    #[tokio::test]
    async fn ipc_client_is_not_running_if_cancellation_token_is_cancelled() {
        let crypto_provider = TestCryptoProvider {
            send_result: None,
            receive_result: None,
        };
        let communication_provider = TestCommunicationBackend::new();
        let session_map = TestSessionRepository::new(HashMap::new());
        let client = IpcClientImpl::new(crypto_provider, communication_provider, session_map);
        let cancellation_token = CancellationToken::new();
        let _ = client.start(Some(cancellation_token.clone())).await;

        // Give the client some time to process
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Cancel the token and give the client some time to process the cancellation
        cancellation_token.cancel();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let is_running = client.is_running();

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
        let client = IpcClientImpl::new(crypto_provider, communication_provider, session_map);
        let cancellation_token = CancellationToken::new();
        let _ = client.start(Some(cancellation_token.clone())).await;

        // Give the client some time to process
        tokio::time::sleep(Duration::from_millis(100)).await;
        let is_running = client.is_running();

        assert!(is_running);
        assert!(!cancellation_token.is_cancelled());
    }

    #[tokio::test]
    async fn ipc_client_is_not_running_if_not_started() {
        let crypto_provider = TestCryptoProvider {
            send_result: None,
            receive_result: None,
        };
        let communication_provider = TestCommunicationBackend::new();
        let session_map = TestSessionRepository::new(HashMap::new());
        let client = IpcClientImpl::new(crypto_provider, communication_provider, session_map);

        // Give the client some time to process
        tokio::time::sleep(Duration::from_millis(100)).await;
        let is_running = client.is_running();

        assert!(!is_running);
    }

    #[tokio::test]
    async fn ipc_client_start_returns_error_if_already_running() {
        let crypto_provider = TestCryptoProvider {
            send_result: None,
            receive_result: None,
        };
        let communication_provider = TestCommunicationBackend::new();
        let session_map = TestSessionRepository::new(HashMap::new());
        let client = IpcClientImpl::new(crypto_provider, communication_provider, session_map);
        let cancellation_token = CancellationToken::new();
        let first_result = client.start(Some(cancellation_token.clone())).await;
        assert_eq!(first_result, Ok(()));

        // Give the client some time to process
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(client.is_running());

        let second_result = client.start(Some(cancellation_token.clone())).await;
        assert_eq!(second_result, Err(AlreadyRunningError));
    }

    mod request {
        use super::*;
        use crate::RpcHandler;

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
            let session_map = InMemorySessionRepository::default();
            let client =
                IpcClientImpl::new(crypto_provider, communication_provider.clone(), session_map);
            let _ = client.start(None).await;
            let request = TestRequest { a: 1, b: 2 };
            let response = TestResponse { result: 3 };

            // Send the request
            let request_clone = request.clone();
            let client_clone = client.clone();
            let result_handle = tokio::spawn(async move {
                client_clone
                    .request::<TestRequest>(
                        request_clone,
                        Endpoint::BrowserBackground { id: HostId::Own },
                        None,
                    )
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
                source: Source::BrowserBackground { id: HostId::Own },
                destination: Endpoint::Web {
                    tab_id: 9001,
                    document_id: "doc-1".to_string(),
                },
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
            let session_map = InMemorySessionRepository::default();
            let client =
                IpcClientImpl::new(crypto_provider, communication_provider.clone(), session_map);
            let _ = client.start(None).await;
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
                source: Source::Web {
                    tab_id: 9001,
                    document_id: "doc-1".to_string(),
                    origin: "https://example.com".to_string(),
                },
                destination: Endpoint::BrowserBackground { id: HostId::Own },
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

use std::time::Duration;

use crate::{
    error::{ReceiveError, SendError, TypedReceiveError},
    message::{IncomingMessage, OutgoingMessage, PayloadTypeName, TypedIncomingMessage},
    traits::{CommunicationBackend, CryptoProvider, SessionRepository},
};

pub struct IpcClient<Crypto, Com, Ses>
where
    Crypto: CryptoProvider<Com, Ses>,
    Com: CommunicationBackend,
    Ses: SessionRepository<Session = Crypto::Session>,
{
    crypto: Crypto,
    communication: Com,
    sessions: Ses,
}

impl<Crypto, Com, Ses> IpcClient<Crypto, Com, Ses>
where
    Crypto: CryptoProvider<Com, Ses>,
    Com: CommunicationBackend,
    Ses: SessionRepository<Session = Crypto::Session>,
{
    pub fn new(crypto: Crypto, communication: Com, sessions: Ses) -> Self {
        Self {
            crypto,
            communication,
            sessions,
        }
    }

    /// Send a message
    pub async fn send(
        &self,
        message: OutgoingMessage,
    ) -> Result<(), SendError<Crypto::SendError, Com::SendError>> {
        self.crypto
            .send(&self.communication, &self.sessions, message)
            .await
    }

    /// Receive a message, optionally filtering by topic.
    /// Setting the topic to `None` will receive all messages.
    /// Setting the timeout to `None` will wait indefinitely.
    pub async fn receive(
        &self,
        topic: Option<String>,
        timeout: Option<Duration>,
    ) -> Result<IncomingMessage, ReceiveError<Crypto::ReceiveError, Com::ReceiveError>> {
        let receive_loop = async {
            loop {
                let received = self
                    .crypto
                    .receive(&self.communication, &self.sessions)
                    .await?;
                if topic.is_none() || received.topic == topic {
                    return Ok(received);
                }
            }
        };

        if let Some(timeout) = timeout {
            tokio::time::timeout(timeout, receive_loop)
                .await
                .map_err(|_| ReceiveError::Timeout)?
        } else {
            receive_loop.await
        }
    }

    /// Receive a message, skipping any messages that cannot be deserialized into the expected
    /// payload type.
    pub async fn receive_typed<Payload>(
        &self,
        timeout: Option<Duration>,
    ) -> Result<
        TypedIncomingMessage<Payload>,
        TypedReceiveError<
            <Payload as TryFrom<Vec<u8>>>::Error,
            Crypto::ReceiveError,
            Com::ReceiveError,
        >,
    >
    where
        Payload: TryFrom<Vec<u8>> + PayloadTypeName,
    {
        let topic = Some(Payload::name());
        let received = self.receive(topic, timeout).await?;
        received.try_into().map_err(TypedReceiveError::Typing)
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
            tests::{TestCommunicationBackend, TestCommunicationBackendReceiveError},
            InMemorySessionRepository, NoEncryptionCryptoProvider,
        },
    };

    struct TestCryptoProvider {
        send_result: Result<(), SendError<String, ()>>,
        receive_result:
            Result<IncomingMessage, ReceiveError<String, TestCommunicationBackendReceiveError>>,
    }

    type TestSessionRepository = InMemorySessionRepository<String>;
    impl CryptoProvider<TestCommunicationBackend, TestSessionRepository> for TestCryptoProvider {
        type Session = String;
        type SendError = String;
        type ReceiveError = String;

        async fn receive(
            &self,
            _communication: &TestCommunicationBackend,
            _sessions: &TestSessionRepository,
        ) -> Result<IncomingMessage, ReceiveError<String, TestCommunicationBackendReceiveError>>
        {
            self.receive_result.clone()
        }

        async fn send(
            &self,
            _communication: &TestCommunicationBackend,
            _sessions: &TestSessionRepository,
            _message: OutgoingMessage,
        ) -> Result<
            (),
            SendError<
                Self::SendError,
                <TestCommunicationBackend as CommunicationBackend>::SendError,
            >,
        > {
            self.send_result.clone()
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
            send_result: Err(SendError::Crypto("Crypto error".to_string())),
            receive_result: Err(ReceiveError::Crypto(
                "Should not have be called".to_string(),
            )),
        };
        let communication_provider = TestCommunicationBackend::new();
        let session_map = TestSessionRepository::new(HashMap::new());
        let client = IpcClient::new(crypto_provider, communication_provider, session_map);

        let error = client.send(message).await.unwrap_err();

        assert_eq!(error, SendError::Crypto("Crypto error".to_string()));
    }

    #[tokio::test]
    async fn returns_receive_error_when_crypto_provider_returns_error() {
        let crypto_provider = TestCryptoProvider {
            send_result: Ok(()),
            receive_result: Err(ReceiveError::Crypto("Crypto error".to_string())),
        };
        let communication_provider = TestCommunicationBackend::new();
        let session_map = TestSessionRepository::new(HashMap::new());
        let client = IpcClient::new(crypto_provider, communication_provider, session_map);

        let error = client.receive(None, None).await.unwrap_err();

        assert_eq!(error, ReceiveError::Crypto("Crypto error".to_string()));
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

        communication_provider.push_incoming(message.clone()).await;
        let received_message = client.receive(None, None).await.unwrap();

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
        communication_provider
            .push_incoming(non_matching_message.clone())
            .await;
        communication_provider
            .push_incoming(non_matching_message.clone())
            .await;
        communication_provider
            .push_incoming(matching_message.clone())
            .await;

        let received_message: IncomingMessage = client
            .receive(Some("matching_topic".to_owned()), None)
            .await
            .unwrap();

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
        communication_provider
            .push_incoming(unrelated.clone())
            .await;
        communication_provider
            .push_incoming(unrelated.clone())
            .await;
        communication_provider
            .push_incoming(typed_message.clone().try_into().unwrap())
            .await;

        let received_message: TypedIncomingMessage<TestPayload> =
            client.receive_typed(None).await.unwrap();

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
        communication_provider
            .push_incoming(non_deserializable_message.clone())
            .await;

        let result: Result<TypedIncomingMessage<TestPayload>, _> = client.receive_typed(None).await;

        assert!(matches!(
            result,
            Err(TypedReceiveError::Typing(serde_json::Error { .. }))
        ));
    }
}

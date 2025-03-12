use crate::{
    error::{ReceiveError, SendError},
    message::{IncomingMessage, OutgoingMessage, TypedIncomingMessage},
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

    /// Receive a message
    pub async fn receive(
        &self,
    ) -> Result<IncomingMessage, ReceiveError<Crypto::ReceiveError, Com::ReceiveError>> {
        self.crypto
            .receive(&self.communication, &self.sessions)
            .await
    }

    /// Receive a message, skipping any messages that cannot be deserialized into the expected
    /// payload type.
    pub async fn receive_typed<Payload>(
        &self,
    ) -> Result<TypedIncomingMessage<Payload>, ReceiveError<Crypto::ReceiveError, Com::ReceiveError>>
    where
        Payload: TryFrom<Vec<u8>>,
    {
        loop {
            let received = self
                .crypto
                .receive(&self.communication, &self.sessions)
                .await?;
            if let Ok(typed) = received.try_into() {
                return Ok(typed);
            }
        }
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
        };
        let crypto_provider = TestCryptoProvider {
            send_result: Err(SendError::CryptoError("Crypto error".to_string())),
            receive_result: Err(ReceiveError::CryptoError(
                "Should not have be called".to_string(),
            )),
        };
        let communication_provider = TestCommunicationBackend::new();
        let session_map = TestSessionRepository::new(HashMap::new());
        let client = IpcClient::new(crypto_provider, communication_provider, session_map);

        let error = client.send(message).await.unwrap_err();

        assert_eq!(error, SendError::CryptoError("Crypto error".to_string()));
    }

    #[tokio::test]
    async fn returns_receive_error_when_crypto_provider_returns_error() {
        let crypto_provider = TestCryptoProvider {
            send_result: Ok(()),
            receive_result: Err(ReceiveError::CryptoError("Crypto error".to_string())),
        };
        let communication_provider = TestCommunicationBackend::new();
        let session_map = TestSessionRepository::new(HashMap::new());
        let client = IpcClient::new(crypto_provider, communication_provider, session_map);

        let error = client.receive().await.unwrap_err();

        assert_eq!(error, ReceiveError::CryptoError("Crypto error".to_string()));
    }

    #[tokio::test]
    async fn communication_provider_has_outgoing_message_when_sending_through_ipc_client() {
        let message = OutgoingMessage {
            payload: vec![],
            destination: Endpoint::BrowserBackground,
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
            source: Endpoint::Web(9001),
            destination: Endpoint::BrowserBackground,
        };
        let crypto_provider = NoEncryptionCryptoProvider;
        let communication_provider = TestCommunicationBackend::new();
        let session_map = InMemorySessionRepository::new(HashMap::new());
        let client = IpcClient::new(crypto_provider, communication_provider.clone(), session_map);

        communication_provider.push_incoming(message.clone()).await;
        let received_message = client.receive().await.unwrap();

        assert_eq!(received_message, message);
    }

    #[tokio::test]
    async fn skips_non_deserializable_messages_and_returns_typed_message() {
        #[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
        struct TestPayload {
            some_data: String,
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
            source: Endpoint::Web(9001),
            destination: Endpoint::BrowserBackground,
        };
        let typed_message = TypedIncomingMessage {
            payload: TestPayload {
                some_data: "Hello, world!".to_string(),
            },
            source: Endpoint::Web(9001),
            destination: Endpoint::BrowserBackground,
        };

        let crypto_provider = NoEncryptionCryptoProvider;
        let communication_provider = TestCommunicationBackend::new();
        let session_map = InMemorySessionRepository::new(HashMap::new());
        let client = IpcClient::new(crypto_provider, communication_provider.clone(), session_map);
        communication_provider
            .push_incoming(non_deserializable_message.clone())
            .await;
        communication_provider
            .push_incoming(non_deserializable_message.clone())
            .await;
        communication_provider
            .push_incoming(typed_message.clone().try_into().unwrap())
            .await;

        let received_message: TypedIncomingMessage<TestPayload> =
            client.receive_typed().await.unwrap();

        assert_eq!(received_message, typed_message);
    }
}

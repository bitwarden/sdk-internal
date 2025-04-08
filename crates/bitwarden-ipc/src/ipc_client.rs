use crate::{
    error::{ReceiveError, SendError},
    message::{IncomingMessage, OutgoingMessage},
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

    pub async fn send(
        &self,
        message: OutgoingMessage,
    ) -> Result<(), SendError<Crypto::SendError, Com::SendError>> {
        self.crypto
            .send(&self.communication, &self.sessions, message)
            .await
    }

    pub async fn receive(
        &self,
    ) -> Result<IncomingMessage, ReceiveError<Crypto::ReceiveError, Com::ReceiveError>> {
        self.crypto
            .receive(&self.communication, &self.sessions)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::{endpoint::Endpoint, traits::InMemorySessionRepository};

    struct TestCommunicationProvider;

    impl CommunicationBackend for TestCommunicationProvider {
        type SendError = ();
        type ReceiveError = ();

        async fn send(&self, _message: OutgoingMessage) -> Result<(), Self::SendError> {
            todo!()
        }

        async fn receive(&self) -> Result<IncomingMessage, Self::ReceiveError> {
            todo!()
        }
    }

    struct TestCryptoProvider {
        send_result: Result<(), SendError<String, ()>>,
        receive_result: Result<IncomingMessage, ReceiveError<String, ()>>,
    }

    type TestSessionRepository = InMemorySessionRepository<String>;
    impl CryptoProvider<TestCommunicationProvider, TestSessionRepository> for TestCryptoProvider {
        type Session = String;
        type SendError = String;
        type ReceiveError = String;

        async fn receive(
            &self,
            _communication: &TestCommunicationProvider,
            _sessions: &TestSessionRepository,
        ) -> Result<IncomingMessage, ReceiveError<String, ()>> {
            self.receive_result.clone()
        }

        async fn send(
            &self,
            _communication: &TestCommunicationProvider,
            _sessions: &TestSessionRepository,
            _message: OutgoingMessage,
        ) -> Result<
            (),
            SendError<
                Self::SendError,
                <TestCommunicationProvider as CommunicationBackend>::SendError,
            >,
        > {
            self.send_result.clone()
        }
    }

    #[tokio::test]
    async fn returns_send_error_when_crypto_provider_returns_error() {
        let message = OutgoingMessage {
            data: vec![],
            destination: Endpoint::BrowserBackground,
        };
        let crypto_provider = TestCryptoProvider {
            send_result: Err(SendError::CryptoError("Crypto error".to_string())),
            receive_result: Err(ReceiveError::CryptoError(
                "Should not have be called".to_string(),
            )),
        };
        let communication_provider = TestCommunicationProvider;
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
        let communication_provider = TestCommunicationProvider;
        let session_map = TestSessionRepository::new(HashMap::new());
        let client = IpcClient::new(crypto_provider, communication_provider, session_map);

        let error = client.receive().await.unwrap_err();

        assert_eq!(error, ReceiveError::CryptoError("Crypto error".to_string()));
    }
}

use crate::{
    error::{ReceiveError, SendError},
    message::Message,
    providers::{CommunicationProvider, CryptoProvider, SessionProvider},
};

pub struct Manager<Crypto, Com, Ses>
where
    Crypto: CryptoProvider<Com, Ses>,
    Com: CommunicationProvider,
    Ses: SessionProvider<Session = Crypto::Session>,
{
    crypto: Crypto,
    communication: Com,
    sessions: Ses,
}

impl<Crypto, Com, Ses> Manager<Crypto, Com, Ses>
where
    Crypto: CryptoProvider<Com, Ses>,
    Com: CommunicationProvider,
    Ses: SessionProvider<Session = Crypto::Session>,
{
    pub fn new(crypto: Crypto, communication: Com, sessions: Ses) -> Self {
        Self {
            crypto,
            communication,
            sessions,
        }
    }

    pub async fn send(
        &mut self,
        message: Message,
    ) -> Result<(), SendError<Crypto::SendError, Com::SendError>> {
        self.crypto
            .send(&self.communication, &mut self.sessions, message)
            .await
    }

    pub async fn receive(
        &mut self,
    ) -> Result<Message, ReceiveError<Crypto::ReceiveError, Com::ReceiveError>> {
        self.crypto
            .receive(&self.communication, &mut self.sessions)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::destination::Destination;

    use super::*;

    struct TestCommunicationProvider;

    impl CommunicationProvider for TestCommunicationProvider {
        type SendError = ();
        type ReceiveError = ();

        async fn send(&self, _message: Message) -> Result<(), Self::SendError> {
            todo!()
        }

        async fn receive(&self) -> Result<Message, Self::ReceiveError> {
            todo!()
        }
    }

    type SessionMap = HashMap<Destination, String>;
    impl SessionProvider for SessionMap {
        type Session = String;

        fn get(&self, destination: Destination) -> Option<Self::Session> {
            self.get(&destination).cloned()
        }

        fn save(&mut self, destination: Destination, session: Self::Session) {
            self.insert(destination, session);
        }

        fn remove(&mut self, destination: Destination) {
            self.remove(&destination);
        }
    }

    struct TestCryptoProvider {
        send_result: Result<(), SendError<String, ()>>,
        receive_result: Result<Message, ReceiveError<String, ()>>,
    }

    impl CryptoProvider<TestCommunicationProvider, SessionMap> for TestCryptoProvider {
        type Session = String;
        type SendError = String;
        type ReceiveError = String;

        async fn receive(
            &self,
            _communication: &TestCommunicationProvider,
            _sessions: &mut SessionMap,
        ) -> Result<Message, ReceiveError<String, ()>> {
            self.receive_result.clone()
        }

        async fn send(
            &self,
            _communication: &TestCommunicationProvider,
            _sessions: &mut SessionMap,
            _message: Message,
        ) -> Result<
            (),
            SendError<
                Self::SendError,
                <TestCommunicationProvider as CommunicationProvider>::SendError,
            >,
        > {
            self.send_result.clone()
        }
    }

    #[tokio::test]
    async fn returns_send_error_when_crypto_provider_returns_error() {
        let message = Message {
            data: vec![],
            destination: Destination::BrowserBackground,
        };
        let crypto_provider = TestCryptoProvider {
            send_result: Err(SendError::CryptoError("Crypto error".to_string())),
            receive_result: Ok(message.clone()),
        };
        let communication_provider = TestCommunicationProvider;
        let session_map = SessionMap::new();
        let mut manager = Manager::new(crypto_provider, communication_provider, session_map);

        let error = manager.send(message).await.unwrap_err();

        assert_eq!(error, SendError::CryptoError("Crypto error".to_string()));
    }

    #[tokio::test]
    async fn returns_receive_error_when_crypto_provider_returns_error() {
        let crypto_provider = TestCryptoProvider {
            send_result: Ok(()),
            receive_result: Err(ReceiveError::CryptoError("Crypto error".to_string())),
        };
        let communication_provider = TestCommunicationProvider;
        let session_map = SessionMap::new();
        let mut manager = Manager::new(crypto_provider, communication_provider, session_map);

        let error = manager.receive().await.unwrap_err();

        assert_eq!(error, ReceiveError::CryptoError("Crypto error".to_string()));
    }
}

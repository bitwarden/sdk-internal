use crate::{
    error::{ReceiveError, SendError},
    message::Message,
    providers::{CommunicationProvider, CryptoProvider},
};

pub struct Manager<Crypto, Com>
where
    Crypto: CryptoProvider<Com>,
    Com: CommunicationProvider,
{
    crypto: Crypto,
    communication: Com,
}

impl<Crypto, Com> Manager<Crypto, Com>
where
    Crypto: CryptoProvider<Com>,
    Com: CommunicationProvider,
{
    pub fn new(crypto: Crypto, communication: Com) -> Self {
        Self {
            crypto,
            communication,
        }
    }

    pub async fn send(
        &self,
        message: Message,
    ) -> Result<(), SendError<Crypto::SendError, Com::SendError>> {
        self.crypto.send(&self.communication, message).await
    }

    pub async fn receive(
        &self,
    ) -> Result<Message, ReceiveError<Crypto::ReceiveError, Com::ReceiveError>> {
        self.crypto.receive(&self.communication).await
    }
}

#[cfg(test)]
mod tests {
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

    struct TestCryptoProvider {
        send_result: Result<(), SendError<String, ()>>,
        receive_result: Result<Message, ReceiveError<String, ()>>,
    }

    impl CryptoProvider<TestCommunicationProvider> for TestCryptoProvider {
        type Session = String;
        type SendError = String;
        type ReceiveError = String;

        async fn receive(
            &self,
            _communication: &TestCommunicationProvider,
        ) -> Result<Message, ReceiveError<String, ()>> {
            self.receive_result.clone()
        }

        async fn send(
            &self,
            _communication: &TestCommunicationProvider,
            // session: &Option<Self::Session>,
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
        let manager = Manager::new(crypto_provider, communication_provider);

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
        let manager = Manager::new(crypto_provider, communication_provider);

        let error = manager.receive().await.unwrap_err();

        assert_eq!(error, ReceiveError::CryptoError("Crypto error".to_string()));
    }
}

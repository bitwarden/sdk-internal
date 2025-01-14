use crate::{
    error::{ReceiveError, SendError},
    message::Message,
};

use super::CommunicationProvider;

pub trait CryptoProvider<Com>
where
    Com: CommunicationProvider,
{
    type Session;
    type SendError;
    type ReceiveError;

    fn send(
        &self,
        communication: &Com,
        // session: &Option<Self::Session>,
        message: Message,
    ) -> impl std::future::Future<Output = Result<(), SendError<Self::SendError, Com::SendError>>>;
    fn receive(
        &self,
        communication: &Com,
        // session: &Option<Self::Session>,
    ) -> impl std::future::Future<
        Output = Result<Message, ReceiveError<Self::ReceiveError, Com::ReceiveError>>,
    >;
}

pub struct NoEncryptionCryptoProvider;

impl<Com> CryptoProvider<Com> for NoEncryptionCryptoProvider
where
    Com: CommunicationProvider,
{
    type Session = ();
    type SendError = Com::SendError;
    type ReceiveError = Com::ReceiveError;

    async fn send(
        &self,
        communication: &Com,
        // _session: &Option<Self::Session>,
        message: Message,
    ) -> Result<(), SendError<Self::SendError, Com::SendError>> {
        communication
            .send(message)
            .await
            .map_err(SendError::CommunicationError)
    }

    async fn receive(
        &self,
        communication: &Com,
        // _session: Option<Self::Session>,
    ) -> Result<Message, ReceiveError<Self::ReceiveError, Com::ReceiveError>> {
        let message = communication
            .receive()
            .await
            .map_err(ReceiveError::CommunicationError);
        message
    }
}

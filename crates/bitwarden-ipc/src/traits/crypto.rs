use crate::{
    error::{ReceiveError, SendError},
    message::Message,
};

use super::{session::SessionRepository, CommunicationBackend};

pub trait CryptoProvider<Com, Ses>
where
    Com: CommunicationBackend,
    Ses: SessionRepository<Session = Self::Session>,
{
    type Session;
    type SendError;
    type ReceiveError;

    fn send(
        &self,
        communication: &Com,
        sessions: &Ses,
        message: Message,
    ) -> impl std::future::Future<Output = Result<(), SendError<Self::SendError, Com::SendError>>>;
    fn receive(
        &self,
        communication: &Com,
        sessions: &Ses,
    ) -> impl std::future::Future<
        Output = Result<Message, ReceiveError<Self::ReceiveError, Com::ReceiveError>>,
    >;
}

pub struct NoEncryptionCryptoProvider;

impl<Com, Ses> CryptoProvider<Com, Ses> for NoEncryptionCryptoProvider
where
    Com: CommunicationBackend,
    Ses: SessionRepository<Session = ()>,
{
    type Session = ();
    type SendError = Com::SendError;
    type ReceiveError = Com::ReceiveError;

    async fn send(
        &self,
        communication: &Com,
        _sessions: &Ses,
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
        _sessions: &Ses,
    ) -> Result<Message, ReceiveError<Self::ReceiveError, Com::ReceiveError>> {
        let message = communication
            .receive()
            .await
            .map_err(ReceiveError::CommunicationError);
        message
    }
}

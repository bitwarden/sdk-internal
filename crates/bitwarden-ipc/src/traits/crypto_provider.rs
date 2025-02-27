use super::{CommunicationBackend, SessionRepository};
use crate::{
    error::{ReceiveError, SendError},
    message::{IncomingMessage, OutgoingMessage},
};

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
        message: OutgoingMessage,
    ) -> impl std::future::Future<Output = Result<(), SendError<Self::SendError, Com::SendError>>>;
    fn receive(
        &self,
        communication: &Com,
        sessions: &Ses,
    ) -> impl std::future::Future<
        Output = Result<IncomingMessage, ReceiveError<Self::ReceiveError, Com::ReceiveError>>,
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
        message: OutgoingMessage,
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
    ) -> Result<IncomingMessage, ReceiveError<Self::ReceiveError, Com::ReceiveError>> {
        communication
            .receive()
            .await
            .map_err(ReceiveError::CommunicationError)
    }
}

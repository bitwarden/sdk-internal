use super::{CommunicationBackend, CommunicationBackendReceiver, SessionRepository};
use crate::{
    error::{ReceiveError, SendError},
    message::{IncomingMessage, OutgoingMessage},
};
use std::fmt::Debug;

pub trait CryptoProvider<Com, Ses>: Send + Sync + 'static
where
    Com: CommunicationBackend,
    Ses: SessionRepository<Self::Session>,
{
    type Session: Send + Sync + 'static;
    type SendError: Debug + Send + Sync + 'static;
    type ReceiveError: Debug + Send + Sync + 'static;

    fn send(
        &self,
        communication: &Com,
        sessions: &Ses,
        message: OutgoingMessage,
    ) -> impl std::future::Future<Output = Result<(), SendError<Self::SendError, Com::SendError>>>;

    fn receive(
        &self,
        receiver: &Com::Receiver,
        communication: &Com,
        sessions: &Ses,
    ) -> impl std::future::Future<
        Output = Result<
            IncomingMessage,
            ReceiveError<
                Self::ReceiveError,
                <Com::Receiver as CommunicationBackendReceiver>::ReceiveError,
            >,
        >,
    > + Send
           + Sync;
}

pub struct NoEncryptionCryptoProvider;

impl<Com, Ses> CryptoProvider<Com, Ses> for NoEncryptionCryptoProvider
where
    Com: CommunicationBackend,
    Ses: SessionRepository<()>,
{
    type Session = ();
    type SendError = Com::SendError;
    type ReceiveError = <Com::Receiver as CommunicationBackendReceiver>::ReceiveError;

    async fn send(
        &self,
        communication: &Com,
        _sessions: &Ses,
        message: OutgoingMessage,
    ) -> Result<(), SendError<Self::SendError, Com::SendError>> {
        communication
            .send(message)
            .await
            .map_err(SendError::Communication)
    }

    async fn receive(
        &self,
        receiver: &Com::Receiver,
        _communication: &Com,
        _sessions: &Ses,
    ) -> Result<
        IncomingMessage,
        ReceiveError<
            Self::ReceiveError,
            <Com::Receiver as CommunicationBackendReceiver>::ReceiveError,
        >,
    > {
        receiver
            .receive()
            .await
            .map_err(ReceiveError::Communication)
    }
}

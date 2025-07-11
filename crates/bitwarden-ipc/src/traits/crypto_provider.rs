use std::fmt::Debug;

use super::{CommunicationBackend, CommunicationBackendReceiver, SessionRepository};
use crate::message::{IncomingMessage, OutgoingMessage};

pub trait CryptoProvider<Com, Ses>: Send + Sync + 'static
where
    Com: CommunicationBackend,
    Ses: SessionRepository<Self::Session>,
{
    type Session: Send + Sync + 'static;
    type SendError: Debug + Send + Sync + 'static;
    type ReceiveError: Debug + Send + Sync + 'static;

    /// Send a message.
    ///
    /// Calling this function may result in multiple messages being sent, depending on the
    /// implementation of the trait. For example, if the destination does not have a
    /// session, the function may first send a message to establish a session and then send the
    /// original message. The implementation of this function should handle this logic.
    ///
    /// An error should only be returned for fatal and unrecoverable errors e.g. if the session
    /// storage is full or cannot be accessed. Returning an error will cause the IPC client to
    /// stop processing messages.
    fn send(
        &self,
        communication: &Com,
        sessions: &Ses,
        message: OutgoingMessage,
    ) -> impl std::future::Future<Output = Result<(), Self::SendError>> + Send;

    /// Receive a message.
    ///
    /// Calling this function may also result in messages being sent, depending on the trait
    /// implementation. For example, if an encrypted message is received from a destination that
    /// does not have a session. The function may then try to establish a session and then
    /// re-request the original message. The implementation of this function should handle this
    /// logic.
    ///
    /// An error should only be returned for fatal and unrecoverable errors e.g. if the session
    /// storage is full or cannot be accessed. Returning an error will cause the IPC client to
    /// stop processing messages.
    fn receive(
        &self,
        receiver: &Com::Receiver,
        communication: &Com,
        sessions: &Ses,
    ) -> impl std::future::Future<Output = Result<IncomingMessage, Self::ReceiveError>> + Send;
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
    ) -> Result<(), Self::SendError> {
        communication.send(message).await
    }

    async fn receive(
        &self,
        receiver: &Com::Receiver,
        _communication: &Com,
        _sessions: &Ses,
    ) -> Result<IncomingMessage, Self::ReceiveError> {
        receiver.receive().await
    }
}

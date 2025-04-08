use crate::message::{IncomingMessage, OutgoingMessage};

/// This trait defines the interface that will be used to send and receive messages over IPC.
/// It is up to the platform to implement this trait and any necessary thread synchronization and
/// broadcasting.
pub trait CommunicationBackend {
    type SendError;
    type ReceiveError;

    /// Send a message to the destination specified in the message. This function may be called
    /// from any thread at any time. The implementation will handle any necessary synchronization.
    fn send(
        &self,
        message: OutgoingMessage,
    ) -> impl std::future::Future<Output = Result<(), Self::SendError>>;

    /// Receive a message. This function will block asynchronously until a message is received.
    /// Multiple calls to this function may be made from different threads, in which case all
    /// threads will receive the same message.
    fn receive(
        &self,
    ) -> impl std::future::Future<Output = Result<IncomingMessage, Self::ReceiveError>>;
}

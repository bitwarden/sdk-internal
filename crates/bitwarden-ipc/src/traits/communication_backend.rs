use crate::message::{IncomingMessage, OutgoingMessage};

/// This trait defines the interface that will be used to send and receive messages over IPC.
/// It is up to the platform to implement this trait and any necessary thread synchronization and
/// broadcasting.
pub trait CommunicationBackend {
    type SendError;
    type Receiver: CommunicationBackendReceiver;

    /// Send a message to the destination specified in the message. This function may be called
    /// from any thread at any time. The implementation will handle any necessary synchronization.
    fn send(
        &self,
        message: OutgoingMessage,
    ) -> impl std::future::Future<Output = Result<(), Self::SendError>>;

    /// Subscribe to receive messages. This function will return a receiver that can be used to
    /// receive messages asynchronously.
    ///
    /// The implemenation of this trait needs to guarantee that:
    ///     - Multiple concurrent receivers may be created.
    ///     - All concurrent receivers will receive the same messages.
    fn subscribe(&self) -> Self::Receiver;
}

/// This trait defines the interface for receiving messages from the communication backend.
///
/// The implemenation of this trait needs to guarantee that:
///     - The receiver buffers messages from the creation of the receiver until the first call to receive().
///     - The receiver buffers messages between calls to receive().
pub trait CommunicationBackendReceiver {
    type ReceiveError;

    /// Receive a message. This function will block asynchronously until a message is received.
    ///
    /// Do not call this function from multiple threads at the same time. Use the subscribe function
    /// to create one receiver per thread.
    fn receive(
        &self,
    ) -> impl std::future::Future<Output = Result<IncomingMessage, Self::ReceiveError>>;
}

#[cfg(test)]
pub mod tests {
    use std::{collections::VecDeque, rc::Rc};

    use thiserror::Error;
    use tokio::sync::RwLock;

    use super::*;

    /// A mock implementation of the CommunicationBackend trait that can be used for testing.
    #[derive(Debug, Clone)]
    pub struct TestCommunicationBackend {
        outgoing: Rc<RwLock<Vec<OutgoingMessage>>>,
        incoming: Rc<RwLock<VecDeque<IncomingMessage>>>,
    }

    impl TestCommunicationBackend {
        pub fn new() -> Self {
            TestCommunicationBackend {
                outgoing: Rc::new(RwLock::new(Vec::new())),
                incoming: Rc::new(RwLock::new(VecDeque::new())),
            }
        }

        /// Add an incoming message to the queue. This message will be returned by the receive
        /// function in the order it was added.
        pub async fn push_incoming(&self, message: IncomingMessage) {
            self.incoming.write().await.push_back(message);
        }

        /// Get a copy of the outgoing messages that have been sent.
        pub async fn outgoing(&self) -> Vec<OutgoingMessage> {
            self.outgoing.read().await.clone()
        }
    }

    #[derive(Debug, Clone, Error, PartialEq)]
    pub enum TestCommunicationBackendReceiveError {
        #[error("Could not receive mock message since no messages were queued")]
        NoQueuedMessages,
    }

    impl CommunicationBackendReceiver for TestCommunicationBackend {
        type ReceiveError = TestCommunicationBackendReceiveError;

        async fn receive(&self) -> Result<IncomingMessage, Self::ReceiveError> {
            if let Some(message) = self.incoming.write().await.pop_front() {
                Ok(message)
            } else {
                Err(TestCommunicationBackendReceiveError::NoQueuedMessages)
            }
        }
    }

    impl CommunicationBackend for TestCommunicationBackend {
        type SendError = ();
        type Receiver = Rc<RwLock<VecDeque<IncomingMessage>>>;

        async fn send(&self, message: OutgoingMessage) -> Result<(), Self::SendError> {
            self.outgoing.write().await.push(message);
            Ok(())
        }

        fn subscribe(&self) -> Self::Receiver {
            Rc::new(RwLock::new(self.incoming.blocking_read().clone()))
        }
    }

    impl CommunicationBackendReceiver for Rc<RwLock<VecDeque<IncomingMessage>>> {
        type ReceiveError = TestCommunicationBackendReceiveError;

        async fn receive(&self) -> Result<IncomingMessage, Self::ReceiveError> {
            if let Some(message) = self.write().await.pop_front() {
                Ok(message)
            } else {
                Err(TestCommunicationBackendReceiveError::NoQueuedMessages)
            }
        }
    }
}

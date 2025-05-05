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
    /// The implementation of this trait needs to guarantee that:
    ///     - Multiple concurrent receivers may be created.
    ///     - All concurrent receivers will receive the same messages.
    fn subscribe(&self) -> impl std::future::Future<Output = Self::Receiver>;
}

/// This trait defines the interface for receiving messages from the communication backend.
///
/// The implementation of this trait needs to guarantee that:
///     - The receiver buffers messages from the creation of the receiver until the first call to
///       receive().
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
    use std::sync::Arc;

    use thiserror::Error;
    use tokio::sync::{
        broadcast::{self, Receiver, Sender},
        RwLock,
    };

    use super::*;

    /// A mock implementation of the CommunicationBackend trait that can be used for testing.
    #[derive(Debug)]
    pub struct TestCommunicationBackend {
        outgoing_tx: Sender<OutgoingMessage>,
        outgoing_rx: Receiver<OutgoingMessage>,
        outgoing: Arc<RwLock<Vec<OutgoingMessage>>>,
        incoming_tx: Sender<IncomingMessage>,
        incoming_rx: Receiver<IncomingMessage>,
    }

    impl Clone for TestCommunicationBackend {
        fn clone(&self) -> Self {
            TestCommunicationBackend {
                outgoing_tx: self.outgoing_tx.clone(),
                outgoing_rx: self.outgoing_rx.resubscribe(),
                outgoing: self.outgoing.clone(),
                incoming_tx: self.incoming_tx.clone(),
                incoming_rx: self.incoming_rx.resubscribe(),
            }
        }
    }

    #[derive(Debug)]
    pub struct TestCommunicationBackendReceiver(RwLock<Receiver<IncomingMessage>>);

    impl TestCommunicationBackend {
        pub fn new() -> Self {
            let (outgoing_tx, outgoing_rx) = broadcast::channel(10);
            let (incoming_tx, incoming_rx) = broadcast::channel(10);
            TestCommunicationBackend {
                outgoing_tx,
                outgoing_rx,
                outgoing: Arc::new(RwLock::new(Vec::new())),
                incoming_tx,
                incoming_rx,
            }
        }

        pub fn push_incoming(&self, message: IncomingMessage) {
            self.incoming_tx
                .send(message)
                .expect("Failed to send incoming message");
        }

        /// Get a copy of all the outgoing messages that have been sent.
        pub async fn outgoing(&self) -> Vec<OutgoingMessage> {
            self.outgoing.read().await.clone()
        }
    }

    #[derive(Debug, Clone, Error, PartialEq)]
    pub enum TestCommunicationBackendReceiveError {
        #[error("Could not receive mock message since no messages were queued")]
        NoQueuedMessages,
    }

    impl CommunicationBackend for TestCommunicationBackend {
        type SendError = ();
        type Receiver = TestCommunicationBackendReceiver;

        async fn send(&self, message: OutgoingMessage) -> Result<(), Self::SendError> {
            self.outgoing.write().await.push(message);
            Ok(())
        }

        async fn subscribe(&self) -> Self::Receiver {
            TestCommunicationBackendReceiver(RwLock::new(self.incoming_rx.resubscribe()))
        }
    }

    impl CommunicationBackendReceiver for TestCommunicationBackendReceiver {
        type ReceiveError = TestCommunicationBackendReceiveError;

        async fn receive(&self) -> Result<IncomingMessage, Self::ReceiveError> {
            let mut receiver = self.0.write().await;

            if receiver.is_empty() {
                return Err(TestCommunicationBackendReceiveError::NoQueuedMessages);
            }

            Ok(receiver
                .recv()
                .await
                .expect("Failed to receive incoming message"))
        }
    }
}

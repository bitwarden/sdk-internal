use std::fmt::Debug;

use crate::message::{IncomingMessage, OutgoingMessage};

/// This trait defines the interface that will be used to send and receive messages over IPC.
/// It is up to the platform to implement this trait and any necessary thread synchronization and
/// broadcasting.
pub trait CommunicationBackend: Send + Sync + 'static {
    type SendError: Debug + Send + Sync + 'static;
    type Receiver: CommunicationBackendReceiver;

    /// Send a message to the destination specified in the message. This function may be called
    /// from any thread at any time.
    ///
    /// An error should only be returned for fatal and unrecoverable errors.
    /// Returning an error will cause the IPC client to stop processing messages.
    ///
    /// The implementation of this trait needs to guarantee that:
    ///     - Multiple concurrent receivers and senders can coexist.
    fn send(
        &self,
        message: OutgoingMessage,
    ) -> impl std::future::Future<Output = Result<(), Self::SendError>> + Send;

    /// Subscribe to receive messages. This function will return a receiver that can be used to
    /// receive messages asynchronously.
    ///
    /// The implementation of this trait needs to guarantee that:
    ///     - Multiple concurrent receivers may be created.
    ///     - All concurrent receivers will receive the same messages.
    ///      - Multiple concurrent receivers and senders can coexist.
    fn subscribe(&self) -> impl std::future::Future<Output = Self::Receiver> + Send;
}

/// This trait defines the interface for receiving messages from the communication backend.
///
/// The implementation of this trait needs to guarantee that:
///     - The receiver buffers messages from the creation of the receiver until the first call to
///       receive().
///     - The receiver buffers messages between calls to receive().
pub trait CommunicationBackendReceiver: Send + Sync + 'static {
    type ReceiveError: Debug + Send + Sync + 'static;

    /// Receive a message. This function will block asynchronously until a message is received.
    ///
    /// An error should only be returned for fatal and unrecoverable errors.
    /// Returning an error will cause the IPC client to stop processing messages.
    ///
    /// Do not call this function from multiple threads at the same time. Use the subscribe function
    /// to create one receiver per thread.
    fn receive(
        &self,
    ) -> impl std::future::Future<Output = Result<IncomingMessage, Self::ReceiveError>> + Send;
}

#[cfg(test)]
pub mod tests {
    use std::sync::Arc;

    use tokio::sync::{
        broadcast::{self, Receiver, Sender}, Mutex, RwLock,
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
        type ReceiveError = ();

        async fn receive(&self) -> Result<IncomingMessage, Self::ReceiveError> {
            Ok(self
                .0
                .write()
                .await
                .recv()
                .await
                .expect("Failed to receive incoming message"))
        }
    }

    #[derive(Clone)]
    pub struct TestTwoWayCommunicationBackend {
        outgoing: broadcast::Sender<OutgoingMessage>,
        receiver: TestTwoWayCommunicationBackendReceiver,
    }

    #[derive(Clone)]
    pub struct TestTwoWayCommunicationBackendReceiver {
        incoming: Arc<Mutex<broadcast::Receiver<OutgoingMessage>>>,
    }

    impl CommunicationBackendReceiver for TestTwoWayCommunicationBackendReceiver {
        type ReceiveError = ();

        async fn receive(&self) -> Result<IncomingMessage, Self::ReceiveError> {
            let mut incoming = self.incoming.lock().await;
            let message = incoming.recv().await.unwrap();
            Ok(IncomingMessage {
                payload: message.payload,
                destination: message.destination,
                source: crate::endpoint::Endpoint::DesktopMain,
                topic: message.topic,
            })
        }
    }

    impl TestTwoWayCommunicationBackend {
        pub fn new() -> (Self, Self) {
            let (outgoing0, incoming0) = broadcast::channel(128);
            let (outgoing1, incoming1) = broadcast::channel(128);
            let one = TestTwoWayCommunicationBackend {
                outgoing: outgoing0,
                receiver: TestTwoWayCommunicationBackendReceiver {
                    incoming: Arc::new(Mutex::new(incoming1)),
                },
            };
            let two = TestTwoWayCommunicationBackend {
                outgoing: outgoing1,
                receiver: TestTwoWayCommunicationBackendReceiver {
                    incoming: Arc::new(Mutex::new(incoming0)),
                },
            };
            (one, two)
        }
    }

    impl CommunicationBackend for TestTwoWayCommunicationBackend {
        type SendError = ();
        type Receiver = TestTwoWayCommunicationBackendReceiver;

        async fn send(&self, message: OutgoingMessage) -> Result<(), Self::SendError> {
            self.outgoing.send(message).unwrap();
            Ok(())
        }

        async fn subscribe(&self) -> Self::Receiver {
            TestTwoWayCommunicationBackendReceiver {
                incoming: Arc::new(Mutex::new(
                    self.receiver.incoming.lock().await.resubscribe(),
                )),
            }
        }
    }
}

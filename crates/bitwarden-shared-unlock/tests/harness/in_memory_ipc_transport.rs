//! The endpoint-routed transport the devices talk over.

use std::{
    collections::HashMap,
    future::pending,
    sync::{Arc, Mutex},
};

use bitwarden_ipc::{
    CommunicationBackend, CommunicationBackendReceiver, Endpoint, ErrorKind, IncomingMessage,
    IpcErrorKind, OutgoingMessage, Source,
};
use tokio::sync::broadcast;

use super::logs::{TopologyId, emit_log, kind};

/// Send error for [`TransportBackend`].
///
/// `kind()` reporting [`ErrorKind::Unreachable`] is what makes the peer's
/// `RequestError::Unreachable` path run, rather than this looking like a generic send failure.
#[derive(Debug)]
pub(crate) enum TransportError {
    Unreachable,
}

impl IpcErrorKind for TransportError {
    fn kind(&self) -> ErrorKind {
        match self {
            TransportError::Unreachable => ErrorKind::Unreachable,
        }
    }
}

pub(super) struct TransportPeer {
    name: String,
    incoming: broadcast::Sender<IncomingMessage>,
}

/// Endpoint-keyed router. Devices register under their own [`Endpoint`]; a send is delivered to
/// whichever device owns `outgoing.destination`, stamped with the sender's [`Source`]. An
/// unregistered destination is unreachable, which is how a test makes a peer unavailable.
pub(crate) struct InMemoryIpcTransport {
    peers: Mutex<HashMap<Endpoint, TransportPeer>>,
    topology: TopologyId,
}

impl InMemoryIpcTransport {
    pub(super) fn new(topology: TopologyId) -> Arc<Self> {
        Arc::new(Self {
            peers: Mutex::new(HashMap::new()),
            topology,
        })
    }

    pub(super) fn register(
        &self,
        endpoint: Endpoint,
        name: &str,
    ) -> broadcast::Sender<IncomingMessage> {
        let (incoming, _) = broadcast::channel(256);
        let mut peers = self.lock_peers();
        assert!(
            !peers.contains_key(&endpoint),
            "Endpoint {endpoint:?} is already claimed; \"{name}\" cannot claim it too"
        );
        peers.insert(
            endpoint,
            TransportPeer {
                name: name.to_owned(),
                incoming: incoming.clone(),
            },
        );
        incoming
    }

    pub(super) fn unregister(&self, endpoint: &Endpoint) {
        self.lock_peers().remove(endpoint);
    }

    fn route(
        &self,
        from_name: &str,
        from_source: &Source,
        message: OutgoingMessage,
    ) -> Result<(), TransportError> {
        let peers = self.lock_peers();
        let Some(peer) = peers.get(&message.destination) else {
            emit_log(
                self.topology,
                from_name,
                kind::IPC_UNREACHABLE,
                None,
                &format!("-> {:?}", message.destination),
            );
            return Err(TransportError::Unreachable);
        };

        emit_log(
            self.topology,
            from_name,
            kind::IPC_SEND,
            None,
            &format!("-> {} ({:?})", peer.name, message.destination),
        );

        // A missing receiver means the message is dropped, not that the peer is unreachable.
        let _ = peer.incoming.send(IncomingMessage {
            payload: message.payload,
            destination: message.destination,
            source: from_source.clone(),
            topic: message.topic,
        });
        Ok(())
    }

    fn lock_peers(&self) -> std::sync::MutexGuard<'_, HashMap<Endpoint, TransportPeer>> {
        self.peers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// One device's end of the transport.
#[derive(Clone)]
pub(super) struct TransportBackend {
    pub(super) transport: Arc<InMemoryIpcTransport>,
    pub(super) name: String,
    pub(super) source: Source,
    pub(super) incoming: broadcast::Sender<IncomingMessage>,
}

pub(super) struct TransportReceiver(tokio::sync::Mutex<broadcast::Receiver<IncomingMessage>>);

impl CommunicationBackend for TransportBackend {
    type SendError = TransportError;
    type Receiver = TransportReceiver;

    async fn send(&self, message: OutgoingMessage) -> Result<(), Self::SendError> {
        self.transport.route(&self.name, &self.source, message)
    }

    async fn subscribe(&self) -> Self::Receiver {
        TransportReceiver(tokio::sync::Mutex::new(self.incoming.subscribe()))
    }
}

impl CommunicationBackendReceiver for TransportReceiver {
    type ReceiveError = TransportError;

    async fn receive(&self) -> Result<IncomingMessage, Self::ReceiveError> {
        loop {
            let received = { self.0.lock().await.recv().await };
            match received {
                Ok(message) => return Ok(message),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                // Only closed when the device is torn down; block forever rather than reporting a
                // fault mid-test.
                Err(broadcast::error::RecvError::Closed) => pending().await,
            }
        }
    }
}

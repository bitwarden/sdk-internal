//! Behavior tests for [`IpcClient::broadcast`].
//!
//! Each test encodes one property of broadcasting: how a group is resolved, when the client
//! refuses to send, and how per-endpoint outcomes are reported.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, broadcast};

use crate::{
    BroadcastError, BroadcastGroup, Endpoint, EndpointSendResult, ErrorKind, HostId,
    IncomingMessage, IpcClient, IpcClientExt, IpcClientImpl, IpcErrorKind,
    NoEncryptionCryptoProvider, NoiseCryptoProvider, NoiseCryptoProviderState,
    NoopCommunicationBackend, OutgoingMessage, PayloadTypeName, SendError, Source,
    traits::{
        BroadcastResolution, CommunicationBackend, CommunicationBackendReceiver,
        InMemorySessionRepository, SessionRepository, TestCommunicationBackend,
    },
};

fn foreground(id: i32) -> Endpoint {
    Endpoint::BrowserForeground { id }
}

fn test_client(
    backend: TestCommunicationBackend,
) -> IpcClientImpl<
    NoEncryptionCryptoProvider,
    TestCommunicationBackend,
    InMemorySessionRepository<()>,
> {
    IpcClientImpl::new(
        NoEncryptionCryptoProvider,
        backend,
        InMemorySessionRepository::new(HashMap::new()),
    )
}

/// A broadcast is fanned out to every resolved endpoint, in resolution order, each with the
/// same payload and topic.
#[tokio::test]
async fn broadcast_sends_to_every_resolved_endpoint() {
    let backend = TestCommunicationBackend::new();
    let endpoints = vec![foreground(1), foreground(2), foreground(3)];
    backend
        .set_resolution(BroadcastResolution::Endpoints(endpoints.clone()))
        .await;
    let client = test_client(backend.clone());

    let results = client
        .broadcast(
            BroadcastGroup::AllBrowserForeground,
            vec![42],
            Some("topic".to_owned()),
        )
        .await
        .expect("group should resolve");

    assert_eq!(
        results,
        endpoints
            .iter()
            .map(|endpoint| EndpointSendResult {
                endpoint: endpoint.clone(),
                result: Ok(()),
            })
            .collect::<Vec<_>>()
    );
    assert_eq!(
        backend.outgoing().await,
        endpoints
            .into_iter()
            .map(|destination| OutgoingMessage {
                payload: vec![42],
                destination,
                topic: Some("topic".to_owned()),
            })
            .collect::<Vec<_>>()
    );
}

/// A group with no members is not an error: nothing is sent and no results are returned.
#[tokio::test]
async fn broadcast_to_group_with_no_members_sends_nothing() {
    let backend = TestCommunicationBackend::new();
    backend
        .set_resolution(BroadcastResolution::Endpoints(vec![]))
        .await;
    let client = test_client(backend.clone());

    let results = client
        .broadcast(BroadcastGroup::AllBrowserForeground, vec![1], None)
        .await
        .expect("an empty group should resolve");

    assert!(results.is_empty());
    assert!(backend.outgoing().await.is_empty());
}

/// A backend that does not override [`CommunicationBackend::resolve`] cannot broadcast: the
/// broadcast fails closed.
#[tokio::test]
async fn default_backend_rejects_broadcast() {
    let client = IpcClientImpl::new(
        NoEncryptionCryptoProvider,
        NoopCommunicationBackend,
        InMemorySessionRepository::<()>::new(HashMap::new()),
    );

    let result = client
        .broadcast(BroadcastGroup::AllBrowserForeground, vec![1], None)
        .await;

    assert_eq!(result, Err(BroadcastError::Unsupported));
}

/// Delegating delivery to another endpoint is not supported: the send fails without delivering
/// anything, including to the delegate.
#[tokio::test]
async fn delegate_resolution_is_rejected_without_sending() {
    let backend = TestCommunicationBackend::new();
    backend
        .set_resolution(BroadcastResolution::Delegate(Endpoint::BrowserBackground {
            id: HostId::Own,
        }))
        .await;
    let client = test_client(backend.clone());

    let result = client
        .broadcast(BroadcastGroup::AllBrowserForeground, vec![1], None)
        .await;

    assert_eq!(result, Err(BroadcastError::DelegationUnsupported));
    assert!(backend.outgoing().await.is_empty());
}

/// A resolution that names an endpoint outside the group is rejected as a whole, so a backend
/// bug cannot leak a message intended for extension pages to, for example, a web page.
#[tokio::test]
async fn out_of_scope_resolution_is_rejected_without_sending() {
    let backend = TestCommunicationBackend::new();
    let web = Endpoint::Web {
        tab_id: 1,
        document_id: "doc".to_owned(),
    };
    backend
        .set_resolution(BroadcastResolution::Endpoints(vec![
            foreground(1),
            web.clone(),
        ]))
        .await;
    let client = test_client(backend.clone());

    let result = client
        .broadcast(BroadcastGroup::AllBrowserForeground, vec![1], None)
        .await;

    assert_eq!(result, Err(BroadcastError::OutOfScope(web)));
    assert!(backend.outgoing().await.is_empty());
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Announcement {
    text: String,
}

impl PayloadTypeName for Announcement {
    const PAYLOAD_TYPE_NAME: &'static str = "Announcement";
}

/// A typed broadcast serializes the payload once and tags every message with the payload type's
/// topic, like a typed unicast send.
#[tokio::test]
async fn typed_broadcast_uses_payload_type_topic() {
    let backend = TestCommunicationBackend::new();
    backend
        .set_resolution(BroadcastResolution::Endpoints(vec![
            foreground(1),
            foreground(2),
        ]))
        .await;
    let client = test_client(backend.clone());

    let results = client
        .broadcast_typed(
            Announcement {
                text: "hello".to_owned(),
            },
            BroadcastGroup::AllBrowserForeground,
        )
        .await
        .expect("group should resolve");

    assert!(results.iter().all(|r| r.result.is_ok()));
    let outgoing = backend.outgoing().await;
    assert_eq!(
        outgoing
            .iter()
            .map(|m| m.destination.clone())
            .collect::<Vec<_>>(),
        vec![foreground(1), foreground(2)]
    );
    for message in outgoing {
        assert_eq!(message.topic.as_deref(), Some("Announcement"));
        let payload: Announcement =
            crate::serde_utils::from_slice(&message.payload).expect("payload should deserialize");
        assert_eq!(payload.text, "hello");
    }
}

// An in-memory network of IPC nodes, used to exercise broadcasting end to end through the
// Noise crypto provider.

/// Routes every outgoing message to the node registered for its destination, labelled with the
/// sender's source. A destination with no registered node is unreachable.
#[derive(Clone, Default)]
struct TestNetwork {
    nodes: Arc<std::sync::Mutex<HashMap<Endpoint, broadcast::Sender<IncomingMessage>>>>,
}

#[derive(Debug)]
struct TestNetworkUnreachable;

impl IpcErrorKind for TestNetworkUnreachable {
    fn kind(&self) -> ErrorKind {
        ErrorKind::Unreachable
    }
}

struct TestNetworkBackend {
    network: TestNetwork,
    source: Source,
    incoming: broadcast::Sender<IncomingMessage>,
    resolution: BroadcastResolution,
}

struct TestNetworkReceiver(Mutex<broadcast::Receiver<IncomingMessage>>);

impl TestNetwork {
    /// Register a node at `source` that resolves every broadcast group to `resolution`.
    fn join(&self, source: Source, resolution: BroadcastResolution) -> TestNetworkBackend {
        let (incoming, _) = broadcast::channel(128);
        self.nodes
            .lock()
            .expect("network lock")
            .insert(source.to_endpoint(), incoming.clone());
        TestNetworkBackend {
            network: self.clone(),
            source,
            incoming,
            resolution,
        }
    }
}

impl CommunicationBackend for TestNetworkBackend {
    type SendError = TestNetworkUnreachable;
    type Receiver = TestNetworkReceiver;

    async fn send(&self, message: OutgoingMessage) -> Result<(), Self::SendError> {
        let destination = self
            .network
            .nodes
            .lock()
            .expect("network lock")
            .get(&message.destination)
            .cloned()
            .ok_or(TestNetworkUnreachable)?;
        // A node with no active subscribers simply drops the message.
        let _ = destination.send(IncomingMessage {
            payload: message.payload,
            destination: message.destination,
            source: self.source.clone(),
            topic: message.topic,
        });
        Ok(())
    }

    async fn resolve(&self, _group: &BroadcastGroup) -> BroadcastResolution {
        self.resolution.clone()
    }

    async fn subscribe(&self) -> Self::Receiver {
        TestNetworkReceiver(Mutex::new(self.incoming.subscribe()))
    }
}

impl CommunicationBackendReceiver for TestNetworkReceiver {
    type ReceiveError = ();

    async fn receive(&self) -> Result<IncomingMessage, Self::ReceiveError> {
        self.0.lock().await.recv().await.map_err(|_| ())
    }
}

/// A session repository whose contents stay inspectable after it is handed to a client.
#[derive(Clone, Default)]
struct SharedSessions(Arc<InMemorySessionRepository<NoiseCryptoProviderState>>);

impl SharedSessions {
    async fn endpoints(&self) -> HashSet<Endpoint> {
        self.0.read().await.keys().cloned().collect()
    }
}

impl SessionRepository<NoiseCryptoProviderState> for SharedSessions {
    type GetError = ();
    type SaveError = ();
    type RemoveError = ();

    async fn get(&self, destination: Endpoint) -> Result<Option<NoiseCryptoProviderState>, ()> {
        self.0.get(destination).await
    }

    async fn save(
        &self,
        destination: Endpoint,
        session: NoiseCryptoProviderState,
    ) -> Result<(), ()> {
        self.0.save(destination, session).await
    }

    async fn remove(&self, destination: Endpoint) -> Result<(), ()> {
        self.0.remove(destination).await
    }
}

type NetworkClient = IpcClientImpl<NoiseCryptoProvider, TestNetworkBackend, SharedSessions>;

async fn start_node(
    network: &TestNetwork,
    source: Source,
    resolution: BroadcastResolution,
) -> (NetworkClient, SharedSessions) {
    let sessions = SharedSessions::default();
    let client = IpcClientImpl::new(
        NoiseCryptoProvider::new(),
        network.join(source, resolution),
        sessions.clone(),
    );
    client.start(None).await.expect("client should start");
    (client, sessions)
}

/// Receive the next message delivered to `client`, failing the test if none arrives promptly.
async fn receive_one(client: &NetworkClient) -> IncomingMessage {
    let mut subscription = client.subscribe(None).await.expect("client is started");
    tokio::time::timeout(Duration::from_secs(5), subscription.receive(None))
        .await
        .expect("message should arrive")
        .expect("receive should succeed")
}

/// A broadcast over encrypted transport establishes one Noise session per resolved peer, and
/// every peer decrypts the same message.
#[tokio::test]
async fn broadcast_fans_out_over_per_peer_encrypted_sessions() {
    let network = TestNetwork::default();
    let peer_ids = [1, 2, 3];
    let mut peers = Vec::new();
    for id in peer_ids {
        let (peer, _) = start_node(
            &network,
            Source::BrowserForeground { id },
            BroadcastResolution::Unsupported,
        )
        .await;
        peers.push(peer);
    }
    let (hub, hub_sessions) = start_node(
        &network,
        Source::BrowserBackground { id: HostId::Own },
        BroadcastResolution::Endpoints(peer_ids.iter().map(|id| foreground(*id)).collect()),
    )
    .await;

    let receivers: Vec<_> = peers
        .iter()
        .cloned()
        .map(|peer| tokio::spawn(async move { receive_one(&peer).await }))
        .collect();
    // Let every peer subscribe before the hub sends.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let results = hub
        .broadcast(
            BroadcastGroup::AllBrowserForeground,
            b"lock".to_vec(),
            Some("topic".to_owned()),
        )
        .await
        .expect("group should resolve");

    assert!(
        results.iter().all(|r| r.result.is_ok()),
        "every send should succeed, got {results:?}"
    );
    assert_eq!(
        hub_sessions.endpoints().await,
        peer_ids.iter().map(|id| foreground(*id)).collect(),
        "the hub should hold exactly one session per resolved peer"
    );
    for receiver in receivers {
        let message = receiver.await.expect("receiver task panicked");
        assert_eq!(message.payload, b"lock".to_vec());
        assert_eq!(message.topic.as_deref(), Some("topic"));
        assert_eq!(
            message.source,
            Source::BrowserBackground { id: HostId::Own }
        );
    }
}

/// An unreachable endpoint (e.g. a popup that closed after resolution) is reported for that
/// endpoint only; delivery to the remaining endpoints, before and after it, still happens.
#[tokio::test]
async fn unreachable_endpoint_does_not_stop_delivery_to_the_others() {
    let network = TestNetwork::default();
    let (peer_1, _) = start_node(
        &network,
        Source::BrowserForeground { id: 1 },
        BroadcastResolution::Unsupported,
    )
    .await;
    let (peer_2, _) = start_node(
        &network,
        Source::BrowserForeground { id: 2 },
        BroadcastResolution::Unsupported,
    )
    .await;
    // Endpoint 99 is resolved but never joined the network.
    let (hub, _) = start_node(
        &network,
        Source::BrowserBackground { id: HostId::Own },
        BroadcastResolution::Endpoints(vec![foreground(1), foreground(99), foreground(2)]),
    )
    .await;

    let receivers: Vec<_> = [peer_1, peer_2]
        .into_iter()
        .map(|peer| tokio::spawn(async move { receive_one(&peer).await }))
        .collect();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let results = hub
        .broadcast(BroadcastGroup::AllBrowserForeground, b"lock".to_vec(), None)
        .await
        .expect("group should resolve");

    assert_eq!(
        results,
        vec![
            EndpointSendResult {
                endpoint: foreground(1),
                result: Ok(()),
            },
            EndpointSendResult {
                endpoint: foreground(99),
                result: Err(SendError::Unreachable),
            },
            EndpointSendResult {
                endpoint: foreground(2),
                result: Ok(()),
            },
        ]
    );
    for receiver in receivers {
        let message = receiver.await.expect("receiver task panicked");
        assert_eq!(message.payload, b"lock".to_vec());
    }
    assert!(
        hub.is_running(),
        "an unreachable peer must not stop the hub"
    );
}

/// A backend whose send to one endpoint fails fatally; every other send succeeds and is recorded.
struct FatalOnEndpointBackend {
    fatal_endpoint: Endpoint,
    resolution: BroadcastResolution,
    attempted: Arc<std::sync::Mutex<Vec<Endpoint>>>,
}

#[derive(Debug)]
struct FatalSendError;

impl IpcErrorKind for FatalSendError {
    fn kind(&self) -> ErrorKind {
        ErrorKind::Fatal
    }
}

impl CommunicationBackend for FatalOnEndpointBackend {
    type SendError = FatalSendError;
    type Receiver = TestNetworkReceiver;

    async fn send(&self, message: OutgoingMessage) -> Result<(), Self::SendError> {
        self.attempted
            .lock()
            .expect("attempted lock")
            .push(message.destination.clone());
        if message.destination == self.fatal_endpoint {
            return Err(FatalSendError);
        }
        Ok(())
    }

    async fn resolve(&self, _group: &BroadcastGroup) -> BroadcastResolution {
        self.resolution.clone()
    }

    async fn subscribe(&self) -> Self::Receiver {
        let (_, receiver) = broadcast::channel(1);
        TestNetworkReceiver(Mutex::new(receiver))
    }
}

/// A fatal error stops the client, so the broadcast stops at the failed endpoint: the endpoints
/// after it are never attempted and are absent from the results.
#[tokio::test]
async fn fatal_error_stops_the_broadcast_at_the_failed_endpoint() {
    let attempted = Arc::new(std::sync::Mutex::new(Vec::new()));
    let client = IpcClientImpl::new(
        NoEncryptionCryptoProvider,
        FatalOnEndpointBackend {
            fatal_endpoint: foreground(2),
            resolution: BroadcastResolution::Endpoints(vec![
                foreground(1),
                foreground(2),
                foreground(3),
            ]),
            attempted: attempted.clone(),
        },
        InMemorySessionRepository::<()>::new(HashMap::new()),
    );

    let results = client
        .broadcast(BroadcastGroup::AllBrowserForeground, vec![1], None)
        .await
        .expect("group should resolve");

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].endpoint, foreground(1));
    assert_eq!(results[0].result, Ok(()));
    assert_eq!(results[1].endpoint, foreground(2));
    assert!(matches!(results[1].result, Err(SendError::Other(_))));
    assert_eq!(
        *attempted.lock().expect("attempted lock"),
        vec![foreground(1), foreground(2)]
    );
}

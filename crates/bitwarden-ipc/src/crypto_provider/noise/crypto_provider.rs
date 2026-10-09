use std::{collections::HashMap, time::Duration};

use bitwarden_threading::time::timeout;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::{
    crypto_provider::noise::{
        handshake::{
            CipherSuite, HandshakeFinishMessage, HandshakeInitiator, HandshakeResponder,
            HandshakeStartMessage,
        },
        transport_state::{PersistentTransportState, TransportFrame},
    },
    endpoint::Endpoint,
    error::{ErrorKind, IpcErrorKind},
    message::{IncomingMessage, OutgoingMessage},
    traits::{
        CommunicationBackend, CommunicationBackendReceiver, CryptoProvider, SessionRepository,
    },
};

/// A `CryptoProvider` that encrypts IPC traffic using the Noise protocol.
#[derive(Default)]
pub struct NoiseCryptoProvider {
    /// Serializes access to the persisted transport state, so that two concurrent sends cannot
    /// read the same copy and reuse a nonce.
    ///
    /// Held per provider, and so per [`IpcClientImpl`](crate::IpcClientImpl), rather than per
    /// process: the state it protects belongs to one client's session repository, and a
    /// process-wide lock would let one client's handshake — which can wait
    /// [`HANDSHAKE_TIMEOUT_SECS`] for a reply — stall every other client's traffic.
    crypto_state_guard: tokio::sync::Mutex<()>,

    /// Handshakes this provider initiated and awaits a reply to, by peer.
    ///
    /// Only the receive path resolves them, so every handshake frame is handled by one consumer,
    /// in arrival order. Held while a session is saved from a handshake, so that registering a
    /// handshake and answering the peer's cannot interleave.
    pending_handshakes: tokio::sync::Mutex<HashMap<Endpoint, PendingHandshake>>,
}

/// A handshake this provider initiated, awaiting the peer's `HandshakeFinish`.
struct PendingHandshake {
    initiator: HandshakeInitiator,

    /// The noise frame of our `HandshakeStart`, carrying our ephemeral public key. Breaks the tie
    /// when the peer initiates at the same time: both peers see both start frames, so both agree
    /// the higher one stays initiator.
    own_start: Vec<u8>,

    /// Dropped with the handshake once it resolves, waking every send waiting on it.
    resolved: tokio::sync::watch::Sender<()>,
}

impl NoiseCryptoProvider {
    /// Creates a provider with no sessions established.
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug)]
pub enum NoiseCryptoProviderError {
    /// A protocol error (missing message, malformed message)
    HandshakeProtocol,
    /// A timeout waiting for a message
    Timeout,
    /// The destination could not be reached (the underlying transport is not connected).
    TransportUnreachable,
    /// Could not send via the underlying transport. `kind` is the underlying backend error's
    /// [`IpcErrorKind`] classification.
    TransportSend { kind: ErrorKind },
    /// Could not receive via the underlying transport. `kind` is the underlying backend error's
    /// [`IpcErrorKind`] classification.
    TransportReceive { kind: ErrorKind },
    /// A cryptographic error. In most cases, such messages are just dropped.
    DecryptionFailure,
}

impl IpcErrorKind for NoiseCryptoProviderError {
    fn kind(&self) -> ErrorKind {
        match self {
            // A bad/missing handshake frame from one peer does not affect the shared client; the
            // peer can retry the handshake.
            NoiseCryptoProviderError::HandshakeProtocol => ErrorKind::Other,
            // The handshake is retryable on a subsequent send.
            NoiseCryptoProviderError::Timeout => ErrorKind::Other,
            // A decryption failure only affects the offending message, which is dropped.
            NoiseCryptoProviderError::DecryptionFailure => ErrorKind::Other,
            // An unreachable destination; the message simply could not be delivered.
            NoiseCryptoProviderError::TransportUnreachable => ErrorKind::Unreachable,
            // Defer to the underlying backend's classification, captured at construction.
            NoiseCryptoProviderError::TransportSend { kind }
            | NoiseCryptoProviderError::TransportReceive { kind } => *kind,
        }
    }
}

/// Classify a transport send failure: an unreachable destination becomes the dedicated
/// [`NoiseCryptoProviderError::TransportUnreachable`], while every other failure preserves the
/// underlying backend's fatal/recoverable classification.
fn transport_send_error<E: IpcErrorKind>(e: E) -> NoiseCryptoProviderError {
    match e.kind() {
        ErrorKind::Unreachable => NoiseCryptoProviderError::TransportUnreachable,
        kind => NoiseCryptoProviderError::TransportSend { kind },
    }
}

impl NoiseCryptoProvider {
    /// Ensures a session with `destination` exists, initiating a handshake unless one is already
    /// in flight, and waits for the receive path to resolve it.
    async fn perform_handshake<Com, Ses>(
        &self,
        communication: &Com,
        sessions: &Ses,
        destination: Endpoint,
    ) -> Result<(), NoiseCryptoProviderError>
    where
        Com: CommunicationBackend,
        Ses: SessionRepository<NoiseCryptoProviderState>,
    {
        let (mut resolved, own_start) = {
            let mut pending_handshakes = self.pending_handshakes.lock().await;

            // The receive path may have answered a handshake from the peer since `send` looked.
            if has_session(sessions, &destination).await {
                return Ok(());
            }

            match pending_handshakes.get(&destination) {
                // Another send to this peer already initiated; wait on that one.
                Some(pending) => (pending.resolved.subscribe(), None),
                None => {
                    let (pending, resolved) =
                        Self::start_handshake(communication, &destination).await?;
                    let own_start = pending.own_start.clone();
                    pending_handshakes.insert(destination.clone(), pending);
                    (resolved, Some(own_start))
                }
            }
        };

        // Resolution drops the sender, so `changed` only returns once the handshake resolved.
        let timed_out = timeout(
            Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
            resolved.changed(),
        )
        .await
        .is_err();

        if timed_out {
            debug!(
                "Noise handshake with {:?} timed out after {} seconds",
                destination, HANDSHAKE_TIMEOUT_SECS
            );

            // Abandon our handshake, unless it resolved meanwhile.
            let mut pending_handshakes = self.pending_handshakes.lock().await;
            if own_start.is_some()
                && pending_handshakes.get(&destination).map(|p| &p.own_start) == own_start.as_ref()
            {
                pending_handshakes.remove(&destination);
            }
        }

        if has_session(sessions, &destination).await {
            return Ok(());
        }

        if timed_out {
            return Err(NoiseCryptoProviderError::Timeout);
        }
        Err(NoiseCryptoProviderError::HandshakeProtocol)
    }

    /// Sends a `HandshakeStart` to `destination`, returning the handshake to register and a
    /// receiver woken once it resolves.
    async fn start_handshake<Com>(
        communication: &Com,
        destination: &Endpoint,
    ) -> Result<(PendingHandshake, tokio::sync::watch::Receiver<()>), NoiseCryptoProviderError>
    where
        Com: CommunicationBackend,
    {
        debug!("Starting noise handshake with {:?}", destination);

        let mut initiator = HandshakeInitiator::new(&CipherSuite::default());
        let message = initiator
            .write_start_message()
            .expect("Handshake start message should be buildable");
        let own_start = message.noise_frame.clone();

        communication
            .send(OutgoingMessage {
                payload: Frame::HandshakeStart(message).to_cbor(),
                destination: destination.clone(),
                topic: None,
            })
            .await
            .map_err(transport_send_error)?;

        let (resolved_tx, resolved) = tokio::sync::watch::channel(());
        let pending = PendingHandshake {
            initiator,
            own_start,
            resolved: resolved_tx,
        };
        Ok((pending, resolved))
    }
}

async fn has_session<Ses>(sessions: &Ses, destination: &Endpoint) -> bool
where
    Ses: SessionRepository<NoiseCryptoProviderState>,
{
    sessions
        .get(destination.clone())
        .await
        .expect("Get session should not fail")
        .is_some()
}

/// Re-handshake interval in seconds. Sessions older than this will automatically
/// re-key on the next send operation.
const REHANDSHAKE_INTERVAL_SECS: u64 = 300;

/// Timeout for waiting for a handshake response from the remote peer.
const HANDSHAKE_TIMEOUT_SECS: u64 = 2;

/// Session state for the Noise crypto provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoiseCryptoProviderState {
    state: PersistentTransportState,
}

impl<Com, Ses> CryptoProvider<Com, Ses> for NoiseCryptoProvider
where
    Com: CommunicationBackend,
    Ses: SessionRepository<NoiseCryptoProviderState>,
{
    type Session = NoiseCryptoProviderState;
    type SendError = NoiseCryptoProviderError;
    type ReceiveError = NoiseCryptoProviderError;

    async fn send(
        &self,
        communication: &Com,
        sessions: &Ses,
        message: OutgoingMessage,
    ) -> Result<(), Self::SendError> {
        // Send operations *MUST* be serialized, otherwise nonce re-use may happen since
        // concurrent sends may acquire the same copy of the transport state before nonce
        // updating.
        let mut _crypto_state_guard = self.crypto_state_guard.lock().await;

        let destination = message.destination.clone();

        let crypto_state = sessions
            .get(destination.clone())
            .await
            .expect("Get session should not fail");

        let mut should_handshake = crypto_state.is_none();
        if let Some(state) = crypto_state.as_ref()
            && state.state.should_rehandshake(REHANDSHAKE_INTERVAL_SECS)
        {
            info!(
                "Noise session with {:?} is older than {}s, re-handshaking",
                destination, REHANDSHAKE_INTERVAL_SECS
            );
            sessions
                .remove(destination.clone())
                .await
                .expect("Delete session should not fail");
            should_handshake = true;
        }

        if should_handshake {
            if crypto_state.is_none() {
                debug!(
                    "Noise handshake with {:?} initiated for new session establishment",
                    destination
                );
            } else {
                debug!(
                    "Noise re-handshake with {:?} due to re-handshake interval",
                    destination
                );
            }

            // Propagate every handshake failure, including an unreachable transport. The
            // unreachable case surfaces as `NoiseCryptoProviderError::TransportUnreachable`
            // (non-fatal), which the logging layers intentionally do not log — so it no longer
            // needs to be swallowed here to avoid spam.
            //
            // The guard is released meanwhile: the receive path resolves the handshake, and must
            // not be stuck behind it decrypting a transport frame.
            drop(_crypto_state_guard);
            self.perform_handshake(communication, sessions, destination.clone())
                .await?;
            _crypto_state_guard = self.crypto_state_guard.lock().await;
        }

        // The session may have been invalidated since the handshake.
        let Some(mut crypto_state) = sessions
            .get(destination.clone())
            .await
            .expect("Get session should not fail")
        else {
            return Err(NoiseCryptoProviderError::HandshakeProtocol);
        };

        // Encrypt and send the payload
        let transport_frame = crypto_state
            .state
            .send(message.payload.into())
            .map_err(|_| NoiseCryptoProviderError::DecryptionFailure)?;
        if let Err(e) = communication
            .send(OutgoingMessage {
                payload: Frame::TransportFrame(transport_frame).to_cbor(),
                destination: destination.clone(),
                topic: message.topic,
            })
            .await
            .map_err(transport_send_error)
        {
            match e.kind() {
                ErrorKind::Fatal => {
                    error!(
                        "{:?} fatal error sending message. Clearing cryptographic sessions.",
                        destination
                    );
                    sessions
                        .remove(destination.clone())
                        .await
                        .expect("Delete session should not fail");
                    return Err(e);
                }
                ErrorKind::Unreachable => {
                    // If a destination goes offline, the cryptographic session is torn down.
                    // The next time the destination comes back online, a new handshake will be
                    // performed. If this were not done, then the first message
                    // would always be dropped by the destination,
                    // after the destination process-reloads because it would not be decryptable by
                    // the destination.
                    info!(
                        "{:?} is unreachable. Clearing cryptographic sessions.",
                        destination
                    );
                    sessions
                        .remove(destination.clone())
                        .await
                        .expect("Delete session should not fail");
                    return Err(e);
                }
                // Every other recoverable send failure is still surfaced.
                ErrorKind::Other => {
                    error!(
                        "Recoverable error sending message to {:?}: {:?}",
                        destination, e
                    );
                }
            }
        }

        sessions
            .save(destination, crypto_state)
            .await
            .expect("Save session should not fail");

        Ok(())
    }

    async fn receive(
        &self,
        receiver: &Com::Receiver,
        communication: &Com,
        sessions: &Ses,
    ) -> Result<IncomingMessage, Self::ReceiveError> {
        loop {
            let message = receiver
                .receive()
                .await
                .map_err(|e| NoiseCryptoProviderError::TransportReceive { kind: e.kind() })?;

            // Ensure session exists
            let source_endpoint: crate::endpoint::Endpoint = message.source.clone().into();

            // Decode outer transport frame from wire
            let Ok(transport_frame) = Frame::from_cbor(&message.payload) else {
                warn!("Received malformed cbor message, ignoring");
                continue;
            };

            match transport_frame {
                Frame::HandshakeStart(handshake_start) => {
                    let mut pending_handshakes = self.pending_handshakes.lock().await;

                    // Both peers initiated at once. The higher start frame stays initiator; the
                    // peer applies the same rule and answers ours instead.
                    if let Some(pending) = pending_handshakes.get(&source_endpoint)
                        && pending.own_start > handshake_start.noise_frame
                    {
                        debug!(
                            "Simultaneous noise handshake with {:?}, keeping ours",
                            source_endpoint
                        );
                        continue;
                    }

                    let mut responder = HandshakeResponder::new(&handshake_start.ciphersuite);
                    responder
                        .read_start_message(&handshake_start)
                        .map_err(|_| NoiseCryptoProviderError::HandshakeProtocol)?;
                    let response_message = responder
                        .write_response_message()
                        .map_err(|_| NoiseCryptoProviderError::HandshakeProtocol)?;
                    let handshake_frame = Frame::HandshakeFinish(response_message);
                    communication
                        .send(OutgoingMessage {
                            payload: handshake_frame.to_cbor(),
                            destination: source_endpoint.clone(),
                            topic: None,
                        })
                        .await
                        .map_err(transport_send_error)?;

                    let crypto_state = NoiseCryptoProviderState {
                        state: (&mut responder).into(),
                    };
                    sessions
                        .save(source_endpoint.clone(), crypto_state)
                        .await
                        .expect("Save session should not fail");

                    // Our own handshake with the peer lost the tie-break, if any; the session just
                    // saved replaces it.
                    if pending_handshakes.remove(&source_endpoint).is_some() {
                        debug!(
                            "Simultaneous noise handshake with {:?}, answered theirs",
                            source_endpoint
                        );
                    }
                }
                Frame::HandshakeFinish(handshake_finish) => {
                    let mut pending_handshakes = self.pending_handshakes.lock().await;

                    // A reply to a handshake that already resolved or timed out.
                    let Some(mut pending) = pending_handshakes.remove(&source_endpoint) else {
                        continue;
                    };

                    if pending
                        .initiator
                        .read_response_message(&handshake_finish)
                        .is_err()
                    {
                        error!("Failed to read handshake response message");
                        return Err(NoiseCryptoProviderError::HandshakeProtocol);
                    }

                    let crypto_state = NoiseCryptoProviderState {
                        state: (&mut pending.initiator).into(),
                    };
                    sessions
                        .save(source_endpoint.clone(), crypto_state)
                        .await
                        .expect("Save session should not fail");

                    info!(
                        "Noise handshake with {:?} completed, session established",
                        source_endpoint
                    );
                }
                Frame::TransportFrame(transport_frame) => {
                    let _crypto_state_guard = self.crypto_state_guard.lock().await;
                    let crypto_state = sessions
                        .get(source_endpoint.clone())
                        .await
                        .expect("Get session should not fail");
                    let Some(mut state) = crypto_state else {
                        debug!("No session for {:?}, waiting for handshake", message.source);
                        let frame = Frame::CryptoInvalidated.to_cbor();
                        communication
                            .send(OutgoingMessage {
                                payload: frame,
                                destination: source_endpoint,
                                topic: None,
                            })
                            .await
                            .map_err(transport_send_error)?;
                        continue;
                    };

                    let payload = state.state.receive(&transport_frame);
                    let Ok(payload) = payload else {
                        info!("Failed to decrypt message from {:?}", message.source);
                        continue;
                    };

                    sessions
                        .save(source_endpoint, state)
                        .await
                        .expect("Save session should not fail");

                    return Ok(IncomingMessage {
                        payload: payload.as_ref().to_vec(),
                        destination: message.destination,
                        source: message.source,
                        topic: message.topic,
                    });
                }
                Frame::CryptoInvalidated => {
                    info!(
                        "Invalidated session for {:?} due to crypto error, deleting session and waiting for handshake",
                        message.source
                    );
                    sessions
                        .remove(source_endpoint)
                        .await
                        .expect("Delete session should not fail");
                }
            }
        }
    }
}

/// The raw frame that is sent via IPC.
#[derive(Serialize, Deserialize)]
pub(super) enum Frame {
    // Handshake Frames
    HandshakeStart(HandshakeStartMessage),
    HandshakeFinish(HandshakeFinishMessage),
    // After the handshake is done, transport frames are used to wrap ciphertexts
    TransportFrame(TransportFrame),
    // If crypto is invalidated, this message is sent by the device noticing
    // the invalidation so that both sides reset the crypto.
    CryptoInvalidated,
}

impl Frame {
    pub(crate) fn to_cbor(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        ciborium::into_writer(self, &mut buffer).expect("Ciborium serialization should not fail");
        buffer
    }

    pub(crate) fn from_cbor(buffer: &[u8]) -> Result<Self, ()> {
        ciborium::from_reader(buffer).map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, time::Duration};

    use crate::{
        IpcClientImpl,
        crypto_provider::noise::crypto_provider::NoiseCryptoProvider,
        endpoint::Endpoint,
        ipc_client_trait::IpcClient,
        message::OutgoingMessage,
        traits::{InMemorySessionRepository, TestTwoWayCommunicationBackend},
    };

    #[tokio::test]
    async fn ping_pong() {
        let (provider_1, provider_2) = TestTwoWayCommunicationBackend::new();

        let session_map_1 = InMemorySessionRepository::new(HashMap::new());
        let client_1 = IpcClientImpl::new(NoiseCryptoProvider::new(), provider_1, session_map_1);
        let _ = client_1.start(None).await;
        let mut recv_1 = client_1.subscribe(None).await.unwrap();

        let session_map_2 = InMemorySessionRepository::new(HashMap::new());
        let client_2 = IpcClientImpl::new(NoiseCryptoProvider::new(), provider_2, session_map_2);
        let _ = client_2.start(None).await;
        let mut recv_2 = client_2.subscribe(None).await.unwrap();

        let handle_1 = tokio::spawn(async move {
            let mut val: u8 = 0;
            for _ in 0..255 {
                let message = OutgoingMessage {
                    payload: vec![val],
                    destination: Endpoint::DesktopMain,
                    topic: None,
                };
                client_1.send(message).await.unwrap();
                let recv_message = recv_1.receive(None).await.unwrap();
                val = recv_message.payload[0] + 1;
            }
        });

        let handle_2 = tokio::spawn(async move {
            for _ in 0..255 {
                let recv_message = recv_2.receive(None).await.unwrap();
                let val = recv_message.payload[0];
                if val == 255 {
                    break;
                }

                client_2
                    .send(OutgoingMessage {
                        payload: vec![val],
                        destination: Endpoint::DesktopMain,
                        topic: None,
                    })
                    .await
                    .unwrap();
            }
        });

        let _ = tokio::join!(handle_1, handle_2);
    }

    /// Both peers lack a session and send at the same time, so both initiate a handshake. They
    /// must still agree on a single session and decrypt each other's messages.
    #[tokio::test]
    async fn simultaneous_handshake_agrees_on_session() {
        const RECEIVE_TIMEOUT: Duration = Duration::from_secs(5);
        const ROUNDS: u8 = 3;

        let (provider_1, provider_2) = TestTwoWayCommunicationBackend::new();

        let session_map_1 = InMemorySessionRepository::new(HashMap::new());
        let client_1 = IpcClientImpl::new(NoiseCryptoProvider::new(), provider_1, session_map_1);
        let _ = client_1.start(None).await;
        let mut recv_1 = client_1.subscribe(None).await.unwrap();

        let session_map_2 = InMemorySessionRepository::new(HashMap::new());
        let client_2 = IpcClientImpl::new(NoiseCryptoProvider::new(), provider_2, session_map_2);
        let _ = client_2.start(None).await;
        let mut recv_2 = client_2.subscribe(None).await.unwrap();

        let message = |val: u8| OutgoingMessage {
            payload: vec![val],
            destination: Endpoint::DesktopMain,
            topic: None,
        };

        // Each round sends from both sides at once; the first round races the handshakes.
        for round in 0..ROUNDS {
            let (sent_1, sent_2) =
                tokio::join!(client_1.send(message(round)), client_2.send(message(round)));
            sent_1.unwrap();
            sent_2.unwrap();

            let received_1 = tokio::time::timeout(RECEIVE_TIMEOUT, recv_1.receive(None))
                .await
                .expect("client 1 should decrypt client 2's message")
                .unwrap();
            let received_2 = tokio::time::timeout(RECEIVE_TIMEOUT, recv_2.receive(None))
                .await
                .expect("client 2 should decrypt client 1's message")
                .unwrap();
            assert_eq!(received_1.payload, vec![round]);
            assert_eq!(received_2.payload, vec![round]);
        }
    }
}

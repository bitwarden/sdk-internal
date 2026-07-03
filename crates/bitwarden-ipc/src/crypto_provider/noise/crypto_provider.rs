use std::time::Duration;

use bitwarden_threading::time::timeout;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::{
    crypto_provider::noise::{
        handshake::{
            CipherSuite, HandshakeFinishMessage, HandshakeInitiator, HandshakeResponder,
            HandshakeStartMessage,
        },
        retransmit_buffer::{BufferedSend, RetransmitBuffer},
        transport_state::{PersistentTransportState, SessionId, TransportFrame},
    },
    error::IpcErrorKind,
    message::{IncomingMessage, OutgoingMessage},
    traits::{
        CommunicationBackend, CommunicationBackendReceiver, CryptoProvider, SessionRepository,
    },
};

/// Noise-based crypto provider for IPC.

#[derive(Default)]
pub struct NoiseCryptoProvider {
    // Serializes all crypto-state access of this provider (its session repository): concurrent
    // operations could otherwise read the same persisted transport state before the nonce is
    // updated, and nonce re-use is a catastrophic cryptographic failure. Scoped to the provider
    // because session repositories are per client; unrelated clients in the same process need
    // no serialization against each other.
    crypto_state_guard: tokio::sync::Mutex<()>,
    // Sent plaintexts retained for retransmission after a session invalidation. Only accessed
    // while `crypto_state_guard` is held and never across an await point
    retransmit_buffer: std::sync::Mutex<RetransmitBuffer>,
}

impl NoiseCryptoProvider {
    /// Creates a new provider
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
    /// Could not send via the underlying transport. `fatal` is derived from the underlying
    /// backend error's [`IpcErrorKind`] classification.
    TransportSend { fatal: bool },
    /// Could not receive via the underlying transport. `fatal` is derived from the underlying
    /// backend error's [`IpcErrorKind`] classification.
    TransportReceive { fatal: bool },
    /// A cryptographic error. In most cases, such messages are just dropped.
    DecryptionFailure,
}

impl IpcErrorKind for NoiseCryptoProviderError {
    fn is_fatal(&self) -> bool {
        match self {
            // A bad/missing handshake frame from one peer does not affect the shared client; the
            // peer can retry the handshake.
            NoiseCryptoProviderError::HandshakeProtocol => false,
            // The handshake is retryable on a subsequent send.
            NoiseCryptoProviderError::Timeout => false,
            // A decryption failure only affects the offending message, which is dropped.
            NoiseCryptoProviderError::DecryptionFailure => false,
            // Defer to the underlying backend's classification, captured at construction.
            NoiseCryptoProviderError::TransportSend { fatal } => *fatal,
            NoiseCryptoProviderError::TransportReceive { fatal } => *fatal,
        }
    }
}

impl NoiseCryptoProvider {
    async fn perform_handshake<Com, Ses>(
        communication: &Com,
        sessions: &Ses,
        destination: crate::endpoint::Endpoint,
    ) -> Result<(), NoiseCryptoProviderError>
    where
        Com: CommunicationBackend,
        Ses: SessionRepository<NoiseCryptoProviderState>,
    {
        info!("Starting noise handshake with {:?}", destination);

        let mut initiator = HandshakeInitiator::new(&CipherSuite::default());
        let message = initiator
            .write_start_message()
            .expect("Handshake start message should be buildable");
        let receiver = communication.subscribe().await;

        let handshake_frame = Frame::HandshakeStart(message);
        communication
            .send(OutgoingMessage {
                payload: handshake_frame.to_cbor(),
                destination: destination.clone(),
                topic: None,
            })
            .await
            .map_err(|e| NoiseCryptoProviderError::TransportSend {
                fatal: e.is_fatal(),
            })?;

        // Wait for the handshake response (with timeout)
        timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), async {
            loop {
                let incoming = receiver.receive().await.map_err(|e| {
                    NoiseCryptoProviderError::TransportReceive {
                        fatal: e.is_fatal(),
                    }
                })?;

                // For concurrent handshakes, ignore messages
                if incoming.source.to_endpoint() != destination {
                    continue;
                }

                // Malformed messages will cancel the handshake
                let Ok(response_frame) = Frame::from_cbor(&incoming.payload) else {
                    return Err(NoiseCryptoProviderError::HandshakeProtocol);
                };

                // Only accept handshake finish messages until the handshake is complete
                if let Frame::HandshakeFinish(handshake_finish) = response_frame {
                    if initiator.read_response_message(&handshake_finish).is_err() {
                        error!("Failed to read handshake response message");
                        return Err(NoiseCryptoProviderError::HandshakeProtocol);
                    }
                    break;
                }
            }
            Ok(())
        })
        .await
        .map_err(|_| {
            info!(
                "Noise handshake with {:?} timed out after {} seconds",
                destination, HANDSHAKE_TIMEOUT_SECS
            );
            NoiseCryptoProviderError::Timeout
            // Both the timeout error, and errors from within the handshake loop are propagated
            // here, hence the double question mark.
        })??;

        let crypto_state = NoiseCryptoProviderState {
            state: (&mut initiator).into(),
        };
        sessions
            .save(destination.clone(), crypto_state)
            .await
            .expect("Save session should not fail");

        info!(
            "Noise handshake with {:?} completed, session established",
            destination
        );

        Ok(())
    }

    /// Encrypts `payload` under the existing session for `destination`, stamps it with
    /// `message_id` and sends it as a transport frame.
    ///
    /// Preconditions: the caller holds the provider's crypto-state guard and a session for
    /// `destination` exists (established by a preceding handshake under the same guard). Takes
    /// no lock itself so it can be shared by `send` and the retransmit recovery path without
    /// double-locking.
    ///
    /// Returns the id of the session the frame was sent under, so callers can tag retransmit
    /// buffer entries.
    async fn encrypt_and_send_with_session<Com, Ses>(
        communication: &Com,
        sessions: &Ses,
        destination: crate::endpoint::Endpoint,
        payload: &[u8],
        topic: Option<String>,
        message_id: u64,
    ) -> Result<SessionId, NoiseCryptoProviderError>
    where
        Com: CommunicationBackend,
        Ses: SessionRepository<NoiseCryptoProviderState>,
    {
        let mut crypto_state = sessions
            .get(destination.clone())
            .await
            .expect("Get session should not fail")
            .expect("Session should exist after handshake");

        let transport_frame = crypto_state
            .state
            .send(payload.to_vec().into(), message_id)
            .map_err(|_| NoiseCryptoProviderError::DecryptionFailure)?;
        let session_id = transport_frame.session_id.clone();
        communication
            .send(OutgoingMessage {
                payload: Frame::TransportFrame(transport_frame).to_cbor(),
                destination: destination.clone(),
                topic,
            })
            .await
            .map_err(|e| NoiseCryptoProviderError::TransportSend {
                fatal: e.is_fatal(),
            })?;

        sessions
            .save(destination, crypto_state)
            .await
            .expect("Save session should not fail");

        Ok(session_id)
    }
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
        let _crypto_state_guard = self.crypto_state_guard.lock().await;

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
            // The old session was healthy, so its buffered messages are presumed delivered, and
            // an invalidation for it can no longer match once the new session is established.
            self.retransmit_buffer
                .lock()
                .expect("Retransmit buffer mutex should not be poisoned")
                .clear_endpoint(&destination);
            should_handshake = true;
        }

        if should_handshake {
            if crypto_state.is_none() {
                info!(
                    "Noise handshake with {:?} initiated for new session establishment",
                    destination
                );
            } else {
                info!(
                    "Noise re-handshake with {:?} due to re-handshake interval",
                    destination
                );
            }

            Self::perform_handshake(communication, sessions, destination.clone()).await?;
        }

        let message_id = self
            .retransmit_buffer
            .lock()
            .expect("Retransmit buffer mutex should not be poisoned")
            .next_message_id(&destination);
        let payload = zeroize::Zeroizing::new(message.payload);

        // Encrypt and send the payload
        let session_id = Self::encrypt_and_send_with_session(
            communication,
            sessions,
            destination.clone(),
            &payload,
            message.topic.clone(),
            message_id,
        )
        .await?;

        // Only a message that actually went out is retained for retransmission; buffering a
        // failed send would duplicate it when the caller retries.
        self.retransmit_buffer
            .lock()
            .expect("Retransmit buffer mutex should not be poisoned")
            .record(
                destination,
                BufferedSend {
                    payload,
                    topic: message.topic,
                    session_id,
                    message_id,
                    retransmissions: 0,
                },
            );

        Ok(())
    }

    async fn receive(
        &self,
        receiver: &Com::Receiver,
        communication: &Com,
        sessions: &Ses,
    ) -> Result<IncomingMessage, Self::ReceiveError> {
        loop {
            let message = receiver.receive().await.map_err(|e| {
                NoiseCryptoProviderError::TransportReceive {
                    fatal: e.is_fatal(),
                }
            })?;

            // Ensure session exists
            let source_endpoint: crate::endpoint::Endpoint = message.source.clone().into();

            // Decode outer transport frame from wire
            let Ok(transport_frame) = Frame::from_cbor(&message.payload) else {
                warn!("Received malformed cbor message, ignoring");
                continue;
            };

            match transport_frame {
                Frame::HandshakeStart(handshake_start) => {
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
                        .map_err(|e| NoiseCryptoProviderError::TransportSend {
                            fatal: e.is_fatal(),
                        })?;

                    let crypto_state = NoiseCryptoProviderState {
                        state: (&mut responder).into(),
                    };
                    sessions
                        .save(source_endpoint, crypto_state)
                        .await
                        .expect("Save session should not fail");
                }
                Frame::TransportFrame(transport_frame) => {
                    let _crypto_state_guard = self.crypto_state_guard.lock().await;
                    let crypto_state = sessions
                        .get(source_endpoint.clone())
                        .await
                        .expect("Get session should not fail");
                    let Some(mut state) = crypto_state else {
                        info!("No session for {:?}, waiting for handshake", message.source);
                        let frame = Frame::CryptoInvalidated {
                            session_id: transport_frame.session_id.clone(),
                            message_id: transport_frame.message_id,
                        }
                        .to_cbor();
                        communication
                            .send(OutgoingMessage {
                                payload: frame,
                                destination: source_endpoint,
                                topic: None,
                            })
                            .await
                            .map_err(|e| NoiseCryptoProviderError::TransportSend {
                                fatal: e.is_fatal(),
                            })?;
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
                Frame::CryptoInvalidated {
                    session_id,
                    message_id,
                } => {
                    let _crypto_state_guard = self.crypto_state_guard.lock().await;
                    let crypto_state = sessions
                        .get(source_endpoint.clone())
                        .await
                        .expect("Get session should not fail");
                    let Some(state) = crypto_state else {
                        info!(
                            "Received CryptoInvalidated from {:?} but no session exists, ignoring",
                            message.source
                        );
                        continue;
                    };
                    // Only an invalidation bound to the *current* session may destroy it.
                    if state.state.session_id() != &session_id {
                        info!(
                            "Received CryptoInvalidated from {:?} for a different session, ignoring",
                            message.source
                        );
                        continue;
                    }
                    info!(
                        "Invalidated session for {:?} due to crypto error, deleting session",
                        message.source
                    );
                    sessions
                        .remove(source_endpoint.clone())
                        .await
                        .expect("Delete session should not fail");

                    // Recover the messages the peer signalled as unprocessed (message id >= the
                    // echoed one): re-establish the session and retransmit them, so the peer
                    // losing its session state does not silently lose messages.
                    let lost = self
                        .retransmit_buffer
                        .lock()
                        .expect("Retransmit buffer mutex should not be poisoned")
                        .take_from(&source_endpoint, &session_id, message_id);
                    info!(
                        "Re-handshaking with {:?} and retransmitting {} message(s) the peer could not process",
                        message.source,
                        lost.len()
                    );
                    if let Err(error) =
                        Self::perform_handshake(communication, sessions, source_endpoint.clone())
                            .await
                    {
                        warn!(
                            ?error,
                            "Recovery re-handshake failed, dropping the peer's lost messages"
                        );
                        continue;
                    }
                    for entry in lost {
                        // A retransmit keeps its original message id: it is the same logical
                        // message, re-sent under a fresh session.
                        match Self::encrypt_and_send_with_session(
                            communication,
                            sessions,
                            source_endpoint.clone(),
                            &entry.payload,
                            entry.topic.clone(),
                            entry.message_id,
                        )
                        .await
                        {
                            Ok(new_session_id) => {
                                // Re-buffer under the fresh session so a peer that loses its
                                // state again mid-recovery gets another chance, bounded by the
                                // per-message retransmission budget.
                                self.retransmit_buffer
                                    .lock()
                                    .expect("Retransmit buffer mutex should not be poisoned")
                                    .record(
                                        source_endpoint.clone(),
                                        BufferedSend {
                                            payload: entry.payload,
                                            topic: entry.topic,
                                            session_id: new_session_id,
                                            message_id: entry.message_id,
                                            retransmissions: entry.retransmissions + 1,
                                        },
                                    );
                            }
                            Err(error) => {
                                // Dropping the remainder preserves per-endpoint ordering: never
                                // send a later message when an earlier one failed.
                                warn!(
                                    ?error,
                                    "Retransmit failed, dropping the remaining lost messages"
                                );
                                break;
                            }
                        }
                    }
                }
                // E.g. a HandshakeFinish already consumed by the per-handshake subscription in
                // `perform_handshake`; its copy in the main loop's receiver is expected noise.
                frame => {
                    tracing::debug!(
                        "Ignoring {} frame in the main receive loop",
                        frame.variant_name()
                    );
                    continue;
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
    // If crypto is invalidated, this message is sent by the device noticing the invalidation so
    // that both sides reset the crypto.
    CryptoInvalidated {
        session_id: SessionId,
        #[serde(default)]
        message_id: u64,
    },
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

    /// Returns the frame variant name for logging, without exposing any payload or key material.
    fn variant_name(&self) -> &'static str {
        match self {
            Frame::HandshakeStart(_) => "HandshakeStart",
            Frame::HandshakeFinish(_) => "HandshakeFinish",
            Frame::TransportFrame(_) => "TransportFrame",
            Frame::CryptoInvalidated { .. } => "CryptoInvalidated",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, time::Duration};

    use super::Frame;
    use crate::{
        IpcClientImpl,
        crypto_provider::noise::{
            crypto_provider::NoiseCryptoProvider,
            handshake::{CipherSuite, HandshakeInitiator, HandshakeResponder},
            transport_state::{
                Payload, PersistentTransportState, SESSION_ID_SIZE, SessionId, TransportFrame,
            },
        },
        endpoint::Endpoint,
        ipc_client_trait::IpcClient,
        message::OutgoingMessage,
        traits::{
            CommunicationBackend, CommunicationBackendReceiver, InMemorySessionRepository,
            TestTwoWayCommunicationBackend,
        },
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

    /// The endpoint under which the scripted peer's frames arrive at the client.
    /// `TestTwoWayCommunicationBackendReceiver` stamps every incoming message with
    /// `Source::DesktopMain`, so the client keys its session for the peer under this endpoint.
    const PEER_ENDPOINT: Endpoint = Endpoint::DesktopMain;

    /// Creates a real noise IPC client on one side of a two-way test backend and returns the
    /// other side as a raw backend for a scripted peer, plus a raw-frame receiver for it.
    async fn client_with_scripted_peer() -> (
        IpcClientImpl<
            NoiseCryptoProvider,
            TestTwoWayCommunicationBackend,
            InMemorySessionRepository<super::NoiseCryptoProviderState>,
        >,
        TestTwoWayCommunicationBackend,
        impl CommunicationBackendReceiver<ReceiveError = ()>,
    ) {
        let (client_backend, peer_backend) = TestTwoWayCommunicationBackend::new();
        // Subscribe the peer before the client is started so no frame can be missed.
        let peer_receiver = peer_backend.subscribe().await;
        let client = IpcClientImpl::new(
            NoiseCryptoProvider::new(),
            client_backend,
            InMemorySessionRepository::new(HashMap::new()),
        );
        client.start(None).await.expect("Client should start");
        (client, peer_backend, peer_receiver)
    }

    /// Receives and decodes the next raw frame arriving at the scripted peer.
    async fn peer_receive_frame(
        peer_receiver: &impl CommunicationBackendReceiver<ReceiveError = ()>,
    ) -> Frame {
        let message = tokio::time::timeout(Duration::from_secs(1), peer_receiver.receive())
            .await
            .expect("Peer should receive a frame in time")
            .expect("Receive should not fail");
        Frame::from_cbor(&message.payload).expect("Peer should receive valid cbor frames")
    }

    /// Sends a raw frame from the scripted peer to the client.
    async fn peer_send_frame(peer_backend: &TestTwoWayCommunicationBackend, frame: Frame) {
        peer_backend
            .send(OutgoingMessage {
                payload: frame.to_cbor(),
                destination: PEER_ENDPOINT,
                topic: None,
            })
            .await
            .expect("Peer send should not fail");
    }

    /// Establishes a session between the client and the scripted peer (peer as honest
    /// responder) by driving one client `send` through the handshake, and verifies the sent
    /// payload decrypts on the peer side. Returns the peer's transport state for the session
    /// and the transport frame the client sent (so tests can echo its ids in invalidations).
    async fn establish_session_with_peer(
        client: &IpcClientImpl<
            NoiseCryptoProvider,
            TestTwoWayCommunicationBackend,
            InMemorySessionRepository<super::NoiseCryptoProviderState>,
        >,
        peer_backend: &TestTwoWayCommunicationBackend,
        peer_receiver: &impl CommunicationBackendReceiver<ReceiveError = ()>,
    ) -> (PersistentTransportState, TransportFrame) {
        let client_for_send = client.clone();
        let send_task = tokio::spawn(async move {
            client_for_send
                .send(OutgoingMessage {
                    payload: b"establish".to_vec(),
                    destination: PEER_ENDPOINT,
                    topic: None,
                })
                .await
        });
        let Frame::HandshakeStart(start) = peer_receive_frame(peer_receiver).await else {
            panic!("Expected HandshakeStart from client");
        };
        let mut responder = HandshakeResponder::new(&start.ciphersuite);
        responder
            .read_start_message(&start)
            .expect("Peer should read HandshakeStart");
        let finish = responder
            .write_response_message()
            .expect("Handshake finish message should be buildable");
        peer_send_frame(peer_backend, Frame::HandshakeFinish(finish)).await;
        let mut peer_session: PersistentTransportState = (&mut responder).into();
        send_task
            .await
            .expect("Send task should not panic")
            .expect("Client send should succeed");
        let Frame::TransportFrame(frame) = peer_receive_frame(peer_receiver).await else {
            panic!("Expected TransportFrame from client");
        };
        assert_eq!(
            peer_session
                .receive(&frame)
                .expect("Established session should decrypt the client's payload")
                .as_ref(),
            b"establish"
        );
        (peer_session, frame)
    }

    /// Scripted-peer half of a handshake: answers the client's `HandshakeStart` as an honest
    /// responder and returns the resulting peer transport state.
    async fn peer_answer_handshake(
        peer_backend: &TestTwoWayCommunicationBackend,
        peer_receiver: &impl CommunicationBackendReceiver<ReceiveError = ()>,
    ) -> PersistentTransportState {
        let Frame::HandshakeStart(start) = peer_receive_frame(peer_receiver).await else {
            panic!("Expected HandshakeStart from client");
        };
        let mut responder = HandshakeResponder::new(&start.ciphersuite);
        responder
            .read_start_message(&start)
            .expect("Peer should read HandshakeStart");
        let finish = responder
            .write_response_message()
            .expect("Handshake finish message should be buildable");
        peer_send_frame(peer_backend, Frame::HandshakeFinish(finish)).await;
        (&mut responder).into()
    }

    /// A delayed/stale `CryptoInvalidated` — generated for a message sent on an *old* session —
    /// must not destroy a *freshly established* session. `CryptoInvalidated` echoes the session
    /// id of the offending transport frame, and the receiver ignores invalidations that do not
    /// match its current session.
    ///
    /// This ordering is realistic even over an in-order transport, because the client consumes
    /// the incoming frame stream through two independent subscribers (the main receive loop and
    /// the per-handshake subscription in `perform_handshake`): the main loop can process a stale
    /// `CryptoInvalidated` *after* the handshake subscription has already completed a new
    /// handshake.
    ///
    /// Sequence: peer restarts (loses its session) → client's msg1 (old session S1) is answered
    /// with `CryptoInvalidated{S1}` → client immediately re-handshakes and retransmits msg1
    /// under fresh S2, then delivers msg2 on the same session → a second, delayed
    /// `CryptoInvalidated{S1}` (for another stale-session message) arrives and must be ignored,
    /// keeping S2 intact.
    #[tokio::test]
    async fn delayed_crypto_invalidated_does_not_destroy_fresh_session() {
        let (client, peer_backend, peer_receiver) = client_with_scripted_peer().await;
        let mut client_subscription = client.subscribe(None).await.unwrap();

        // Establish a healthy session S1 (peer as honest responder).
        let client_for_send = client.clone();
        let send_task = tokio::spawn(async move {
            client_for_send
                .send(OutgoingMessage {
                    payload: b"msg0".to_vec(),
                    destination: PEER_ENDPOINT,
                    topic: None,
                })
                .await
        });
        let Frame::HandshakeStart(start_1) = peer_receive_frame(&peer_receiver).await else {
            panic!("Expected HandshakeStart from client");
        };
        let mut responder_1 = HandshakeResponder::new(&start_1.ciphersuite);
        responder_1
            .read_start_message(&start_1)
            .expect("Peer should read HandshakeStart");
        let finish_1 = responder_1
            .write_response_message()
            .expect("Handshake finish message should be buildable");
        peer_send_frame(&peer_backend, Frame::HandshakeFinish(finish_1)).await;
        let mut peer_session_1: PersistentTransportState = (&mut responder_1).into();
        send_task
            .await
            .expect("Send task should not panic")
            .expect("Client send should succeed");
        let Frame::TransportFrame(frame_msg0) = peer_receive_frame(&peer_receiver).await else {
            panic!("Expected TransportFrame(msg0) from client");
        };
        assert_eq!(
            peer_session_1
                .receive(&frame_msg0)
                .expect("Session S1 should decrypt msg0")
                .as_ref(),
            b"msg0"
        );

        // Peer "restarts": it forgets S1. The client's next message is encrypted under S1, so
        // the restarted peer answers with CryptoInvalidated (this is the designed reset path).
        client
            .send(OutgoingMessage {
                payload: b"msg1".to_vec(),
                destination: PEER_ENDPOINT,
                topic: None,
            })
            .await
            .expect("Client send should succeed");
        let Frame::TransportFrame(stale_frame) = peer_receive_frame(&peer_receiver).await else {
            panic!("Expected TransportFrame(msg1) from client");
        };
        // A restarted peer has no session, so it echoes the offending frame's session and
        // message id (S1, msg1). The client immediately re-handshakes to retransmit the lost
        // msg1 — the peer answers as responder.
        peer_send_frame(
            &peer_backend,
            Frame::CryptoInvalidated {
                session_id: stale_frame.session_id.clone(),
                message_id: stale_frame.message_id,
            },
        )
        .await;
        let Frame::HandshakeStart(start_2) = peer_receive_frame(&peer_receiver).await else {
            panic!("Expected recovery HandshakeStart from client");
        };
        let mut responder_2 = HandshakeResponder::new(&start_2.ciphersuite);
        responder_2
            .read_start_message(&start_2)
            .expect("Peer should read HandshakeStart");
        let finish_2 = responder_2
            .write_response_message()
            .expect("Handshake finish message should be buildable");
        peer_send_frame(&peer_backend, Frame::HandshakeFinish(finish_2)).await;
        let mut peer_session_2: PersistentTransportState = (&mut responder_2).into();

        // The lost msg1 is retransmitted under fresh S2 (msg0 was confirmed delivered by the
        // echoed message id and is not resent).
        let Frame::TransportFrame(frame_msg1) = peer_receive_frame(&peer_receiver).await else {
            panic!("Expected retransmitted TransportFrame(msg1) from client");
        };
        assert_eq!(
            peer_session_2
                .receive(&frame_msg1)
                .expect("Session S2 should decrypt the retransmitted msg1")
                .as_ref(),
            b"msg1"
        );

        // The client's next send reuses S2 — no further handshake — and msg2 is delivered.
        client
            .send(OutgoingMessage {
                payload: b"msg2".to_vec(),
                destination: PEER_ENDPOINT,
                topic: None,
            })
            .await
            .expect("Client send should succeed");
        let Frame::TransportFrame(frame_msg2) = peer_receive_frame(&peer_receiver).await else {
            panic!("Expected TransportFrame(msg2) from client");
        };
        assert_eq!(
            peer_session_2
                .receive(&frame_msg2)
                .expect("Session S2 should decrypt msg2")
                .as_ref(),
            b"msg2"
        );

        // A second, *delayed* CryptoInvalidated for S1 arrives (in production: generated for
        // another message sent on stale S1, but processed by the main receive loop only after
        // the re-handshake completed). It must NOT affect the healthy session S2.
        peer_send_frame(
            &peer_backend,
            Frame::CryptoInvalidated {
                session_id: stale_frame.session_id.clone(),
                message_id: stale_frame.message_id,
            },
        )
        .await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }

        // Session S2 survives the stale invalidation, so the peer's next message is decrypted
        // and delivered.
        let peer_frame = peer_session_2
            .send(Payload(b"after-stale-invalidation".to_vec()), 1)
            .expect("Peer encryption should succeed");
        peer_send_frame(&peer_backend, Frame::TransportFrame(peer_frame)).await;
        let received = tokio::time::timeout(
            Duration::from_secs(1),
            client_subscription.receive(None),
        )
        .await
        .expect(
            "the fresh session must survive a stale CryptoInvalidated and deliver the peer's \
                 message, but nothing was delivered (the fresh session was destroyed)",
        )
        .expect("Receive should not fail");
        assert_eq!(received.payload, b"after-stale-invalidation");
    }

    /// A `CryptoInvalidated` bound to a session id *different* from the client's current session
    /// must be ignored: the session survives and stays usable in both directions, without any
    /// re-handshake.
    #[tokio::test]
    async fn crypto_invalidated_with_mismatched_session_id_is_ignored() {
        let (client, peer_backend, peer_receiver) = client_with_scripted_peer().await;
        let mut client_subscription = client.subscribe(None).await.unwrap();
        let (mut peer_session, _) =
            establish_session_with_peer(&client, &peer_backend, &peer_receiver).await;

        // An invalidation for some *other* session must not affect the current one.
        let wrong_id = SessionId([0xAB; SESSION_ID_SIZE]);
        assert_ne!(
            &wrong_id,
            peer_session.session_id(),
            "precondition: the fabricated id must differ from the current session's id"
        );
        peer_send_frame(
            &peer_backend,
            Frame::CryptoInvalidated {
                session_id: wrong_id,
                message_id: 1,
            },
        )
        .await;
        // Let the client's receive loop process the invalidation deterministically
        // (current-thread test runtime: yielding runs all ready tasks).
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }

        // Peer -> client still decrypts and delivers.
        let peer_frame = peer_session
            .send(Payload(b"still-alive".to_vec()), 1)
            .expect("Peer encryption should succeed");
        peer_send_frame(&peer_backend, Frame::TransportFrame(peer_frame)).await;
        let received = tokio::time::timeout(
            Duration::from_secs(1),
            client_subscription.receive(None),
        )
        .await
        .expect(
            "the session must survive a mismatched CryptoInvalidated, but nothing was delivered",
        )
        .expect("Receive should not fail");
        assert_eq!(received.payload, b"still-alive");

        // Client -> peer still uses the same session: the next send must be a transport frame,
        // not a re-handshake.
        client
            .send(OutgoingMessage {
                payload: b"no-rehandshake".to_vec(),
                destination: PEER_ENDPOINT,
                topic: None,
            })
            .await
            .expect("Client send should succeed");
        let Frame::TransportFrame(frame) = peer_receive_frame(&peer_receiver).await else {
            panic!(
                "Expected TransportFrame — a HandshakeStart would mean the session was wrongly \
                 invalidated"
            );
        };
        assert_eq!(
            peer_session
                .receive(&frame)
                .expect("The surviving session should decrypt the client's payload")
                .as_ref(),
            b"no-rehandshake"
        );
    }

    /// A `CryptoInvalidated` carrying the client's *current* session id is the designed reset
    /// path: the client deletes the session, immediately re-handshakes, and transparently
    /// retransmits the message the peer could not process — keeping its original message id —
    /// so a peer that lost its session state loses no messages. Subsequent sends reuse the
    /// fresh session without another handshake.
    #[tokio::test]
    async fn crypto_invalidated_with_current_session_id_invalidates_and_retransmits() {
        let (client, peer_backend, peer_receiver) = client_with_scripted_peer().await;
        let (peer_session, establish_frame) =
            establish_session_with_peer(&client, &peer_backend, &peer_receiver).await;

        // The peer "lost" its session: it echoes the offending frame's session and message id.
        peer_send_frame(
            &peer_backend,
            Frame::CryptoInvalidated {
                session_id: peer_session.session_id().clone(),
                message_id: establish_frame.message_id,
            },
        )
        .await;

        // The client immediately starts a recovery handshake; the peer answers it.
        let mut new_peer_session = peer_answer_handshake(&peer_backend, &peer_receiver).await;
        assert_ne!(
            peer_session.session_id(),
            new_peer_session.session_id(),
            "the re-handshake must establish a session with a new id"
        );

        // The lost message is retransmitted under the new session with its original message id.
        let Frame::TransportFrame(retransmitted) = peer_receive_frame(&peer_receiver).await else {
            panic!("Expected the lost message to be retransmitted as a TransportFrame");
        };
        assert_eq!(
            retransmitted.message_id, establish_frame.message_id,
            "a retransmitted message must keep its original message id"
        );
        assert_eq!(
            new_peer_session
                .receive(&retransmitted)
                .expect("The new session should decrypt the retransmitted payload")
                .as_ref(),
            b"establish"
        );

        // The next send reuses the fresh session: a transport frame, not another handshake.
        client
            .send(OutgoingMessage {
                payload: b"after-reset".to_vec(),
                destination: PEER_ENDPOINT,
                topic: None,
            })
            .await
            .expect("Client send should succeed");
        let Frame::TransportFrame(frame) = peer_receive_frame(&peer_receiver).await else {
            panic!("Expected TransportFrame — the recovery already re-established the session");
        };
        assert_eq!(
            new_peer_session
                .receive(&frame)
                .expect("The new session should decrypt the client's payload")
                .as_ref(),
            b"after-reset"
        );
    }

    /// The echoed message id is the retransmission cursor: everything the peer processed (lower
    /// ids) stays confirmed, everything from the echoed id onwards is retransmitted in order.
    #[tokio::test]
    async fn retransmit_starts_at_the_echoed_message_id() {
        let (client, peer_backend, peer_receiver) = client_with_scripted_peer().await;
        let (mut peer_session, establish_frame) =
            establish_session_with_peer(&client, &peer_backend, &peer_receiver).await;

        // Two more messages; the peer processes "a" but "restarts" before processing "b".
        for payload in [b"a".to_vec(), b"b".to_vec()] {
            client
                .send(OutgoingMessage {
                    payload,
                    destination: PEER_ENDPOINT,
                    topic: None,
                })
                .await
                .expect("Client send should succeed");
        }
        let Frame::TransportFrame(frame_a) = peer_receive_frame(&peer_receiver).await else {
            panic!("Expected TransportFrame(a) from client");
        };
        assert_eq!(
            peer_session
                .receive(&frame_a)
                .expect("Session should decrypt a")
                .as_ref(),
            b"a"
        );
        let Frame::TransportFrame(frame_b) = peer_receive_frame(&peer_receiver).await else {
            panic!("Expected TransportFrame(b) from client");
        };

        // The restarted peer echoes the first frame it could not process: "b".
        peer_send_frame(
            &peer_backend,
            Frame::CryptoInvalidated {
                session_id: frame_b.session_id.clone(),
                message_id: frame_b.message_id,
            },
        )
        .await;

        let mut new_peer_session = peer_answer_handshake(&peer_backend, &peer_receiver).await;

        // Only "b" is retransmitted: "establish" and "a" were confirmed by the echoed id.
        let Frame::TransportFrame(retransmitted) = peer_receive_frame(&peer_receiver).await else {
            panic!("Expected the lost message to be retransmitted as a TransportFrame");
        };
        assert_eq!(retransmitted.message_id, frame_b.message_id);
        assert_eq!(
            new_peer_session
                .receive(&retransmitted)
                .expect("The new session should decrypt the retransmitted payload")
                .as_ref(),
            b"b"
        );
        assert!(
            establish_frame.message_id < frame_b.message_id,
            "precondition: message ids increment per endpoint"
        );
        // No further frame follows: nothing below the echoed id is resent.
        tokio::time::timeout(Duration::from_millis(200), peer_receiver.receive())
            .await
            .expect_err("messages confirmed by the echoed id must not be retransmitted");
    }

    /// If the recovery handshake fails (peer unreachable), the lost messages are dropped — the
    /// pre-recovery behavior — and the channel stays usable: a later send re-handshakes and
    /// goes through.
    #[tokio::test]
    async fn failed_recovery_handshake_drops_buffered_payloads() {
        let (client, peer_backend, peer_receiver) = client_with_scripted_peer().await;
        let (peer_session, establish_frame) =
            establish_session_with_peer(&client, &peer_backend, &peer_receiver).await;

        peer_send_frame(
            &peer_backend,
            Frame::CryptoInvalidated {
                session_id: peer_session.session_id().clone(),
                message_id: establish_frame.message_id,
            },
        )
        .await;

        // The client starts a recovery handshake, but the peer never answers; the handshake
        // times out (HANDSHAKE_TIMEOUT_SECS) and the buffered message is dropped.
        let Frame::HandshakeStart(_) = peer_receive_frame(&peer_receiver).await else {
            panic!("Expected recovery HandshakeStart from client");
        };
        tokio::time::sleep(Duration::from_secs(super::HANDSHAKE_TIMEOUT_SECS + 1)).await;

        // A later send re-handshakes and only the new payload arrives.
        let client_for_send = client.clone();
        let send_task = tokio::spawn(async move {
            client_for_send
                .send(OutgoingMessage {
                    payload: b"new".to_vec(),
                    destination: PEER_ENDPOINT,
                    topic: None,
                })
                .await
        });
        let mut new_peer_session = peer_answer_handshake(&peer_backend, &peer_receiver).await;
        send_task
            .await
            .expect("Send task should not panic")
            .expect("Client send should succeed");
        let Frame::TransportFrame(frame) = peer_receive_frame(&peer_receiver).await else {
            panic!("Expected TransportFrame from client");
        };
        assert_eq!(
            new_peer_session
                .receive(&frame)
                .expect("The new session should decrypt the payload")
                .as_ref(),
            b"new"
        );
        // The dropped message is not resent.
        tokio::time::timeout(Duration::from_millis(200), peer_receiver.receive())
            .await
            .expect_err("messages dropped after a failed recovery must not reappear");
    }

    /// A client that receives a transport frame for which it holds *no* session replies with
    /// `CryptoInvalidated` echoing the offending frame's session id and message id, so the
    /// sender can reset exactly the session the frame belongs to and retransmit from exactly
    /// the first message the receiver could not process.
    #[tokio::test]
    async fn sessionless_receiver_echoes_offending_session_and_message_id() {
        let (_client, peer_backend, peer_receiver) = client_with_scripted_peer().await;

        // Build a session the client knows nothing about (peer handshakes with itself) and send
        // the client a transport frame from it.
        let ciphersuite = CipherSuite::default();
        let mut initiator = HandshakeInitiator::new(&ciphersuite);
        let start = initiator
            .write_start_message()
            .expect("Handshake start message should be buildable");
        let mut responder = HandshakeResponder::new(&ciphersuite);
        responder
            .read_start_message(&start)
            .expect("Responder should read HandshakeStart");
        let finish = responder
            .write_response_message()
            .expect("Handshake finish message should be buildable");
        initiator
            .read_response_message(&finish)
            .expect("Initiator should read HandshakeFinish");
        let mut orphan_session: PersistentTransportState = (&mut initiator).into();

        let frame = orphan_session
            .send(Payload(b"hello?".to_vec()), 7)
            .expect("Peer encryption should succeed");
        let expected_id = frame.session_id.clone();
        peer_send_frame(&peer_backend, Frame::TransportFrame(frame)).await;

        let Frame::CryptoInvalidated {
            session_id,
            message_id,
        } = peer_receive_frame(&peer_receiver).await
        else {
            panic!("Expected CryptoInvalidated for a transport frame without a session");
        };
        assert_eq!(
            session_id, expected_id,
            "the invalidation must echo the offending frame's session id"
        );
        assert_eq!(
            message_id, 7,
            "the invalidation must echo the offending frame's message id"
        );
    }
}

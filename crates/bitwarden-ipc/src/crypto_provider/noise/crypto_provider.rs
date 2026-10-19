use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard},
    time::Duration,
};

use bitwarden_threading::time::timeout;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};

use crate::{
    crypto_provider::noise::{
        handshake::{
            CipherSuite, HandshakeFinishMessage, HandshakeInitiator, HandshakeResponder,
            HandshakeStartMessage,
        },
        transport_state::{PersistentTransportState, ReceiveError, TransportFrame},
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
    /// Handshakes this side started and the receive loop has not completed yet.
    ///
    /// Only the receive loop completes handshakes and saves their sessions, so every decision is
    /// taken in wire order. If both peers start a handshake toward each other, both keep the one
    /// with the greater start frame:
    ///
    /// ```text
    /// A ── start_A ──►   ◄── start_B ── B         start_A > start_B
    /// A: start_B arrives, pending start_A wins  → ignore it
    /// B: start_A arrives, pending start_B loses → respond, save responder session
    /// A: finish arrives                         → save initiator session
    /// ```
    pending_handshakes: Mutex<HashMap<Endpoint, PendingHandshake>>,
}

/// A handshake waiting for the peer's [`Frame::HandshakeFinish`].
struct PendingHandshake {
    initiator: HandshakeInitiator,
    /// Our start frame, compared against the peer's when both start a handshake at once.
    start: Vec<u8>,
    /// Resolved once a session with the peer is saved.
    established: oneshot::Sender<()>,
}

impl NoiseCryptoProvider {
    /// Creates a provider with no sessions established.
    pub fn new() -> Self {
        Self::default()
    }

    fn pending(&self) -> MutexGuard<'_, HashMap<Endpoint, PendingHandshake>> {
        self.pending_handshakes
            .lock()
            .expect("Pending handshakes lock should not be poisoned")
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
    async fn perform_handshake<Com>(
        &self,
        communication: &Com,
        destination: Endpoint,
    ) -> Result<(), NoiseCryptoProviderError>
    where
        Com: CommunicationBackend,
    {
        debug!("Starting noise handshake with {:?}", destination);

        let mut initiator = HandshakeInitiator::new(&CipherSuite::default());
        let message = initiator
            .write_start_message()
            .expect("Handshake start message should be buildable");

        // Registered before sending, so the receive loop always finds it for the response.
        let (established, established_rx) = oneshot::channel();
        self.pending().insert(
            destination.clone(),
            PendingHandshake {
                initiator,
                start: message.noise_frame.clone(),
                established,
            },
        );

        let handshake_frame = Frame::HandshakeStart(message);
        if let Err(e) = communication
            .send(OutgoingMessage {
                payload: handshake_frame.to_cbor(),
                destination: destination.clone(),
                topic: None,
            })
            .await
            .map_err(transport_send_error)
        {
            self.pending().remove(&destination);
            return Err(e);
        }

        // The receive loop completes the handshake and saves the session.
        match timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), established_rx).await {
            Ok(Ok(())) => {}
            // The receive loop dropped the handshake on a malformed response.
            Ok(Err(_)) => return Err(NoiseCryptoProviderError::HandshakeProtocol),
            Err(_) => {
                self.pending().remove(&destination);
                debug!(
                    "Noise handshake with {:?} timed out after {} seconds",
                    destination, HANDSHAKE_TIMEOUT_SECS
                );
                return Err(NoiseCryptoProviderError::Timeout);
            }
        }

        info!(
            "Noise handshake with {:?} completed, session established",
            destination
        );

        Ok(())
    }

    /// Drops our session with `endpoint` and tells it to drop its own, so the next send
    /// re-handshakes.
    async fn invalidate_session<Com, Ses>(
        communication: &Com,
        sessions: &Ses,
        endpoint: Endpoint,
    ) -> Result<(), NoiseCryptoProviderError>
    where
        Com: CommunicationBackend,
        Ses: SessionRepository<NoiseCryptoProviderState>,
    {
        sessions
            .remove(endpoint.clone())
            .await
            .expect("Delete session should not fail");
        communication
            .send(OutgoingMessage {
                payload: Frame::CryptoInvalidated.to_cbor(),
                destination: endpoint,
                topic: None,
            })
            .await
            .map_err(transport_send_error)
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
            self.perform_handshake(communication, destination.clone())
                .await?;
        }

        let mut crypto_state = sessions
            .get(destination.clone())
            .await
            .expect("Get session should not fail")
            .expect("Session should exist after handshake");

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
                    // Both sides started a handshake toward each other and ours wins, see
                    // `pending_handshakes`. The peer answers ours and drops its own.
                    let ours_wins = self
                        .pending()
                        .get(&source_endpoint)
                        .is_some_and(|pending| pending.start > handshake_start.noise_frame);
                    if ours_wins {
                        debug!(
                            "Concurrent handshake with {:?}, keeping ours",
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

                    // Our own handshake lost, if any: the responder session replaces it.
                    let pending = self.pending().remove(&source_endpoint);
                    if let Some(pending) = pending {
                        let _ = pending.established.send(());
                    }
                }
                Frame::HandshakeFinish(handshake_finish) => {
                    // Without a pending handshake the response is for one that timed out.
                    let pending = self.pending().remove(&source_endpoint);
                    let Some(mut pending) = pending else {
                        continue;
                    };
                    if pending
                        .initiator
                        .read_response_message(&handshake_finish)
                        .is_err()
                    {
                        error!("Failed to read handshake response message");
                        continue;
                    }

                    let crypto_state = NoiseCryptoProviderState {
                        state: (&mut pending.initiator).into(),
                    };
                    sessions
                        .save(source_endpoint, crypto_state)
                        .await
                        .expect("Save session should not fail");
                    let _ = pending.established.send(());
                }
                Frame::TransportFrame(transport_frame) => {
                    // The frame belongs to the session being replaced. Waiting for
                    // `crypto_state_guard`, held by the send awaiting our handshake, would stop
                    // this loop from completing that handshake.
                    if self.pending().contains_key(&source_endpoint) {
                        debug!("Dropping frame from {:?} during handshake", message.source);
                        continue;
                    }

                    let _crypto_state_guard = self.crypto_state_guard.lock().await;
                    let crypto_state = sessions
                        .get(source_endpoint.clone())
                        .await
                        .expect("Get session should not fail");
                    let Some(mut state) = crypto_state else {
                        debug!("No session for {:?}, waiting for handshake", message.source);
                        Self::invalidate_session(communication, sessions, source_endpoint).await?;
                        continue;
                    };

                    let payload = match state.state.receive(&transport_frame) {
                        Ok(payload) => payload,
                        // The peer encrypted with a session we do not hold.
                        Err(ReceiveError::Decryption) => {
                            info!(
                                "Failed to decrypt message from {:?}, invalidating session",
                                message.source
                            );
                            Self::invalidate_session(communication, sessions, source_endpoint)
                                .await?;
                            continue;
                        }
                        Err(ReceiveError::NonceReplay) => {
                            info!("Failed to decrypt message from {:?}", message.source);
                            continue;
                        }
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
    use std::collections::HashMap;

    use crate::{
        IpcClientImpl,
        crypto_provider::noise::{
            crypto_provider::{NoiseCryptoProvider, NoiseCryptoProviderState},
            transport_state::{PersistentTransportState, SymmetricKey, TransportCipher},
        },
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

    const RECEIVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

    fn message(val: u8) -> OutgoingMessage {
        OutgoingMessage {
            payload: vec![val],
            destination: Endpoint::DesktopMain,
            topic: None,
        }
    }

    /// Two peers with no session that send to each other at the same time each start a handshake;
    /// every message sent afterwards must still be delivered.
    #[tokio::test]
    async fn concurrent_handshakes_deliver_messages() {
        const ROUNDS: u8 = 5;

        let (provider_1, provider_2) = TestTwoWayCommunicationBackend::new();

        let client_1 = IpcClientImpl::new(
            NoiseCryptoProvider::new(),
            provider_1,
            InMemorySessionRepository::new(HashMap::new()),
        );
        let _ = client_1.start(None).await;
        let mut recv_1 = client_1.subscribe(None).await.unwrap();

        let client_2 = IpcClientImpl::new(
            NoiseCryptoProvider::new(),
            provider_2,
            InMemorySessionRepository::new(HashMap::new()),
        );
        let _ = client_2.start(None).await;
        let mut recv_2 = client_2.subscribe(None).await.unwrap();

        // Both sides start a handshake toward each other before either has a session.
        let (sent_1, sent_2) = tokio::join!(client_1.send(message(0)), client_2.send(message(100)));
        assert!(
            sent_1.is_ok() && sent_2.is_ok(),
            "trigger not reached: both concurrent sends should succeed ({sent_1:?}, {sent_2:?})"
        );

        // Every message sent after the concurrent handshake must arrive.
        let mut delivered = 0;
        for round in 1..=ROUNDS {
            client_1.send(message(round)).await.unwrap();
            client_2.send(message(100 + round)).await.unwrap();
        }
        for _ in 0..=ROUNDS {
            if tokio::time::timeout(RECEIVE_TIMEOUT, recv_2.receive(None))
                .await
                .is_ok()
            {
                delivered += 1;
            }
            if tokio::time::timeout(RECEIVE_TIMEOUT, recv_1.receive(None))
                .await
                .is_ok()
            {
                delivered += 1;
            }
        }

        assert_eq!(
            delivered,
            2 * (ROUNDS as usize + 1),
            "every message sent after concurrent handshakes should be delivered"
        );
    }

    /// Peers holding sessions that do not pair drop the undecryptable frame, then re-handshake
    /// instead of dropping every frame until the re-handshake interval.
    #[tokio::test]
    async fn decrypt_failure_rehandshakes() {
        const KEY_SIZE: usize = 32;

        // Each side's receive key differs from the other side's send key.
        let unpaired = |send: u8, receive: u8| NoiseCryptoProviderState {
            state: PersistentTransportState::new(
                SymmetricKey([send; KEY_SIZE]),
                SymmetricKey([receive; KEY_SIZE]),
                TransportCipher::default(),
            ),
        };
        let sessions =
            |state| InMemorySessionRepository::new(HashMap::from([(Endpoint::DesktopMain, state)]));

        let (provider_1, provider_2) = TestTwoWayCommunicationBackend::new();

        let client_1 = IpcClientImpl::new(
            NoiseCryptoProvider::new(),
            provider_1,
            sessions(unpaired(1, 2)),
        );
        let _ = client_1.start(None).await;

        let client_2 = IpcClientImpl::new(
            NoiseCryptoProvider::new(),
            provider_2,
            sessions(unpaired(3, 4)),
        );
        let _ = client_2.start(None).await;
        let mut recv_2 = client_2.subscribe(None).await.unwrap();

        // The first frame cannot be decrypted and is dropped.
        client_1.send(message(1)).await.unwrap();
        assert!(
            tokio::time::timeout(RECEIVE_TIMEOUT, recv_2.receive(None))
                .await
                .is_err(),
            "trigger not reached: a frame sent over unpaired sessions should be dropped"
        );

        // The next frame travels over a fresh session.
        client_1.send(message(2)).await.unwrap();
        let received = tokio::time::timeout(RECEIVE_TIMEOUT, recv_2.receive(None))
            .await
            .expect("message after a decrypt failure should be delivered")
            .unwrap();
        assert_eq!(received.payload, vec![2]);
    }
}

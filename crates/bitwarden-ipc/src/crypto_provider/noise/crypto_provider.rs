use std::{sync::LazyLock, time::Duration};

use bitwarden_threading::time::timeout;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::{
    ReachabilityTracker,
    crypto_provider::noise::{
        handshake::{
            CipherSuite, HandshakeFinishMessage, HandshakeInitiator, HandshakeResponder,
            HandshakeStartMessage,
        },
        transport_state::{PersistentTransportState, TransportFrame},
    },
    error::IpcErrorKind,
    message::{IncomingMessage, OutgoingMessage},
    reachability::is_reachability_topic,
    traits::{
        CommunicationBackend, CommunicationBackendReceiver, CryptoProvider, SessionRepository,
    },
};

pub struct NoiseCryptoProvider;

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

// Serialize send operations to prevent concurrent reads of the same persisted
// transport state, which can cause nonce reuse.
static CRYPTO_STATE_GUARD: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));

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
        reachability: &ReachabilityTracker,
        message: OutgoingMessage,
    ) -> Result<(), Self::SendError> {
        // Send operations *MUST* be serialized, otherwise nonce re-use may happen since
        // concurrent sends may acquire the same copy of the transport state before nonce
        // updating.
        let _crypto_state_guard = CRYPTO_STATE_GUARD.lock().await;

        let destination = message.destination.clone();

        let crypto_state = sessions
            .get(destination.clone())
            .await
            .expect("Get session should not fail");

        let reachable = reachability.is_reachable(&destination);

        let mut should_handshake = crypto_state.is_none();

        // Not reachable, drop the message
        if !reachable {
            info!(
                "Destination {:?} is not reachable; dropping message without attempting handshake",
                destination
            );
            return Ok(());
        }

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
        communication
            .send(OutgoingMessage {
                payload: Frame::TransportFrame(transport_frame).to_cbor(),
                destination: destination.clone(),
                topic: message.topic,
            })
            .await
            .map_err(|e| NoiseCryptoProviderError::TransportSend {
                fatal: e.is_fatal(),
            })?;

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
            let message = receiver.receive().await.map_err(|e| {
                NoiseCryptoProviderError::TransportReceive {
                    fatal: e.is_fatal(),
                }
            })?;

            // Plaintext reachability ping/pong travels over the raw transport and must NOT be
            // decoded as a Noise frame. Pass it straight through; the IPC client handles it.
            if is_reachability_topic(message.topic.as_deref()) {
                return Ok(message);
            }

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
                    let _crypto_state_guard = CRYPTO_STATE_GUARD.lock().await;
                    let crypto_state = sessions
                        .get(source_endpoint.clone())
                        .await
                        .expect("Get session should not fail");
                    let Some(mut state) = crypto_state else {
                        info!("No session for {:?}, waiting for handshake", message.source);
                        let frame = Frame::CryptoInvalidated.to_cbor();
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
                _ => continue,
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
        reachability::is_reachability_topic,
        traits::{
            InMemorySessionRepository, TestCommunicationBackend, TestTwoWayCommunicationBackend,
        },
    };

    #[tokio::test]
    async fn ping_pong() {
        let (provider_1, provider_2) = TestTwoWayCommunicationBackend::new();

        let session_map_1 = InMemorySessionRepository::new(HashMap::new());
        let client_1 = IpcClientImpl::new(NoiseCryptoProvider, provider_1, session_map_1);
        let _ = client_1.start(None).await;
        let mut recv_1 = client_1.subscribe(None).await.unwrap();

        let session_map_2 = InMemorySessionRepository::new(HashMap::new());
        let client_2 = IpcClientImpl::new(NoiseCryptoProvider, provider_2, session_map_2);
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
}

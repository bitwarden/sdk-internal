use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use tracing::info;

use crate::{
    crypto_provider::noise::{
        handshake::{
            CipherSuite, HandshakeFinishMessage, HandshakeInitiator, HandshakeResponder,
            HandshakeStartMessage,
        },
        transport_state::{PersistentTransportState, TransportFrame},
    },
    message::{IncomingMessage, OutgoingMessage},
    traits::{
        CommunicationBackend, CommunicationBackendReceiver, CryptoProvider, SessionRepository,
    },
};

pub struct NoiseCryptoProvider;

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
    type SendError = ();
    type ReceiveError = ();

    async fn send(
        &self,
        communication: &Com,
        sessions: &Ses,
        message: OutgoingMessage,
    ) -> Result<(), Self::SendError> {
        let destination = message.destination;

        let crypto_state = sessions
            .get(destination)
            .await
            .expect("Get session should not fail");

        let mut should_handshake = crypto_state.is_none();
        if let Some(state) = crypto_state.as_ref()
            && state.state.should_rehandshake(REHANDSHAKE_INTERVAL_SECS)
        {
            info!(
                "[IPC Crypto] Session with {:?} is older than {}s, re-handshaking",
                destination, REHANDSHAKE_INTERVAL_SECS
            );
            sessions
                .remove(destination)
                .await
                .expect("Delete session should not fail");
            should_handshake = true;
        }

        if should_handshake {
            if crypto_state.is_none() {
                info!(
                    "[IPC Crypto] No session for {:?}, starting handshake",
                    destination
                );
            }
            let mut initiator = HandshakeInitiator::new(&CipherSuite::default());
            let message = initiator
                .write_start_message()
                .expect("Handshake start message should be buildable");
            let handshake_frame = Frame::HandshakeStart(message);
            communication
                .send(OutgoingMessage {
                    payload: handshake_frame.to_cbor(),
                    destination,
                    topic: None,
                })
                .await
                .map_err(|_| ())?;
            // Wait for the handshake response (with timeout)
            let receiver = communication.subscribe().await;
            timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), async {
                loop {
                    let incoming = receiver.receive().await.map_err(|_| ()).unwrap();
                    let Ok(response_frame) = Frame::from_cbor(&incoming.payload) else {
                        continue;
                    };
                    if let Frame::HandshakeFinish(handshake_finish) = response_frame {
                        initiator.read_response_message(&handshake_finish).unwrap();
                        break;
                    }
                }
            })
            .await
            .map_err(|_| ())?;
            let crypto_state = NoiseCryptoProviderState {
                state: (&mut initiator).into(),
            };
            sessions
                .save(destination, crypto_state)
                .await
                .expect("Save session should not fail");
            info!(
                "[IPC Crypto] Handshake with {:?} completed, session established",
                destination
            );
        }

        let mut crypto_state = sessions
            .get(destination)
            .await
            .expect("Get session should not fail")
            .expect("Session should exist after handshake");

        // Encrypt and send the payload
        let transport_frame = crypto_state
            .state
            .send(message.payload.into())
            .map_err(|_| ())?;
        communication
            .send(OutgoingMessage {
                payload: Frame::TransportFrame(transport_frame).to_cbor(),
                destination,
                topic: message.topic,
            })
            .await
            .map_err(|_| ())?;

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
            let message = receiver.receive().await.map_err(|_| ())?;

            // Ensure session exists
            let crypto_state = sessions
                .get(message.source)
                .await
                .expect("Get session should not fail");

            // Decode outer transport frame from wire
            let Ok(transport_frame) = Frame::from_cbor(&message.payload) else {
                println!(
                    "Failed to decode frame from {:?}, ignoring message",
                    message.source
                );
                continue;
            };

            match transport_frame {
                Frame::HandshakeStart(handshake_start) => {
                    println!("Received handshake start from {:?}", message.source);
                    let mut responder = HandshakeResponder::new(&CipherSuite::default());
                    responder
                        .read_start_message(&handshake_start)
                        .map_err(|_| ())?;
                    let response_message = responder.write_response_message().map_err(|_| ())?;
                    let handshake_frame = Frame::HandshakeFinish(response_message);
                    communication
                        .send(OutgoingMessage {
                            payload: handshake_frame.to_cbor(),
                            destination: message.source,
                            topic: None,
                        })
                        .await
                        .map_err(|_| ())?;

                    let crypto_state = NoiseCryptoProviderState {
                        state: (&mut responder).into(),
                    };
                    sessions
                        .save(message.source, crypto_state)
                        .await
                        .expect("Save session should not fail");
                }
                Frame::TransportFrame(transport_frame) => {
                    let crypto_state = crypto_state;
                    let Some(mut state) = crypto_state else {
                        info!("No session for {:?}, waiting for handshake", message.source);
                        let frame = Frame::CryptoInvalidated.to_cbor();
                        communication
                            .send(OutgoingMessage {
                                payload: frame,
                                destination: message.source,
                                topic: None,
                            })
                            .await
                            .map_err(|_| ())?;
                        continue;
                    };

                    let payload = state.state.receive(&transport_frame).map_err(|_| ())?;
                    sessions
                        .save(message.source, state)
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
                        .remove(message.source)
                        .await
                        .expect("Delete session should not fail");
                }
                _ => continue,
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
enum Frame {
    HandshakeStart(HandshakeStartMessage),
    HandshakeFinish(HandshakeFinishMessage),
    TransportFrame(TransportFrame),
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
        IpcClient,
        crypto_provider::noise::crypto_provider::NoiseCryptoProvider,
        endpoint::Endpoint,
        message::OutgoingMessage,
        traits::{InMemorySessionRepository, tests::TestTwoWayCommunicationBackend},
    };

    #[tokio::test]
    async fn ping_pong() {
        let (provider_1, provider_2) = TestTwoWayCommunicationBackend::new();

        let session_map_1 = InMemorySessionRepository::new(HashMap::new());
        let client_1 = IpcClient::new(NoiseCryptoProvider, provider_1, session_map_1);
        client_1.start().await;
        let mut recv_1 = client_1.subscribe(None).await.unwrap();

        let session_map_2 = InMemorySessionRepository::new(HashMap::new());
        let client_2 = IpcClient::new(NoiseCryptoProvider, provider_2, session_map_2);
        client_2.start().await;
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

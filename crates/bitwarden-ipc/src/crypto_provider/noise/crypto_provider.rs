use serde::{Deserialize, Serialize};

use crate::{
    crypto_provider::noise::{
        state_machine::{NoiseStateMachine, ReceiveResult},
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

/// Session state for the Noise crypto provider.
///
/// Wraps a [`NoiseStateMachine`] and provides custom serialization that persists only the current
/// transport state. In-flight handshake state is intentionally lost on serialization and will be
/// restarted on the next send.
pub struct NoiseCryptoProviderState {
    state: NoiseStateMachine,
}

impl Clone for NoiseCryptoProviderState {
    fn clone(&self) -> Self {
        // Lossy clone: drops in-flight handshake state; reconstructs from the current transport
        // state. This is safe because handshakes are transient and will be re-initiated.
        Self {
            state: NoiseStateMachine::from_transport_state(self.state.transport_state().clone()),
        }
    }
}

impl Serialize for NoiseCryptoProviderState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.state.transport_state().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NoiseCryptoProviderState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let transport_state = PersistentTransportState::deserialize(deserializer)?;
        Ok(Self {
            state: NoiseStateMachine::from_transport_state(transport_state),
        })
    }
}

impl NoiseCryptoProviderState {
    fn new() -> Self {
        Self {
            state: NoiseStateMachine::new_initial(),
        }
    }
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

        // Create session if none exists
        let mut crypto_state = crypto_state.unwrap_or_else(NoiseCryptoProviderState::new);

        // Auto-trigger handshake if not yet completed, or re-handshake if the session is stale
        if crypto_state.state.needs_handshake()
            || crypto_state
                .state
                .needs_rehandshake(REHANDSHAKE_INTERVAL_SECS)
        {
            let handshake_frame = crypto_state.state.start_handshake().map_err(|_| ())?;
            communication
                .send(OutgoingMessage {
                    payload: handshake_frame.to_cbor(),
                    destination,
                    topic: None,
                })
                .await
                .map_err(|_| ())?;

            // Wait for the handshake response
            let receiver = communication.subscribe().await;
            loop {
                let incoming = receiver.receive().await.map_err(|_| ())?;
                let Ok(response_frame) = TransportFrame::from_cbor(&incoming.payload) else {
                    continue;
                };
                match crypto_state.state.receive(response_frame) {
                    Ok(ReceiveResult::Nothing) => break,
                    Ok(_) | Err(_) => continue,
                }
            }
        }

        // Encrypt and send the payload
        let transport_frame = crypto_state
            .state
            .send(message.payload.into())
            .map_err(|_| ())?;
        communication
            .send(OutgoingMessage {
                payload: transport_frame.to_cbor(),
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
            let mut crypto_state = crypto_state.unwrap_or_else(NoiseCryptoProviderState::new);

            // Decode outer transport frame from wire
            let Ok(transport_frame) = TransportFrame::from_cbor(&message.payload) else {
                continue;
            };

            // Feed the frame into the state machine
            match crypto_state.state.receive(transport_frame) {
                Ok(ReceiveResult::ReceivedMessage { payload }) => {
                    sessions
                        .save(message.source, crypto_state)
                        .await
                        .expect("Save session should not fail");
                    return Ok(IncomingMessage {
                        payload: payload.0,
                        destination: message.destination,
                        source: message.source,
                        topic: message.topic,
                    });
                }
                Ok(ReceiveResult::NeedsMessageSent {
                    message: response_frame,
                }) => {
                    // Send the handshake response back to the source
                    let _ = communication
                        .send(OutgoingMessage {
                            payload: response_frame.to_cbor(),
                            destination: message.source,
                            topic: None,
                        })
                        .await;
                    sessions
                        .save(message.source, crypto_state)
                        .await
                        .expect("Save session should not fail");
                    continue;
                }
                Ok(ReceiveResult::Nothing) => {
                    sessions
                        .save(message.source, crypto_state)
                        .await
                        .expect("Save session should not fail");
                    continue;
                }
                Err(_) => {
                    // Don't save on error to avoid overwriting valid session state
                    // (e.g. a concurrent handshake completed by the send path)
                    continue;
                }
            }
        }
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

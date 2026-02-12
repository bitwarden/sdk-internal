use std::vec;

use serde::{Deserialize, Serialize};
use tracing::error;

use crate::{
    crypto_provider::noise::{
        error::{HandshakeError, PayloadError},
        messages::{BitwardenNoiseFrame, TransportMessage},
        persistent_transport_state::PersistentTransportState,
    },
    endpoint::Endpoint,
    message::{IncomingMessage, OutgoingMessage},
    traits::{
        CommunicationBackend, CommunicationBackendReceiver, CryptoProvider, SessionRepository,
    },
};

const CIPHER_SUITE: &str = "Noise_NN_25519_ChaChaPoly_BLAKE2s";

pub struct NoiseCryptoProvider;

#[derive(Clone, Debug, Serialize, Deserialize)]
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
        message: crate::message::OutgoingMessage,
    ) -> Result<(), Self::SendError> {
        let crypto_state = sessions
            .get(message.destination)
            .await
            .expect("Get session should not fail");

        // Connect if no session exists
        let mut crypto_state = if let Some(crypto_state) = crypto_state {
            crypto_state
        } else {
            let crypto_state = connect(communication, message.destination)
                .await
                .map_err(|_| ())?;
            sessions
                .save(message.destination, crypto_state.clone())
                .await
                .expect("Save session should not fail");
            crypto_state
        };

        // Encrypt and send the message
        if let Err(e) = send_payload(communication, &mut crypto_state, message).await {
            error!("[IPC send] Failed to send message: {e:?}");
        }

        Ok(())
    }

    async fn receive(
        &self,
        receiver: &Com::Receiver,
        communication: &Com,
        sessions: &Ses,
    ) -> Result<IncomingMessage, Self::ReceiveError> {
        loop {
            // Decode the message. If receiving returns error, then this also returns error.
            let message = receiver.receive().await.map_err(|_| ())?;
            let payload = BitwardenNoiseFrame::from_cbor(&message.payload);
            let Ok(payload) = payload else {
                // Discard invalid messages
                continue;
            };

            match payload {
                BitwardenNoiseFrame::NoiseHandshakeStart {
                    ciphersuite,
                    payload,
                } => {
                    let state = incoming_handshake(
                        communication,
                        ciphersuite,
                        payload.to_vec(),
                        message.source,
                    )
                    .await;
                    let Ok(state) = state else {
                        continue;
                    };

                    sessions
                        .save(message.source, state)
                        .await
                        .expect("Save session should not fail");
                }
                BitwardenNoiseFrame::NoiseTransportMessage { payload } => {
                    let crypto_state = sessions
                        .get(message.source)
                        .await
                        .expect("Get session should not fail");
                    let Some(mut crypto_state) = crypto_state else {
                        // If no session exists, we cannot decrypt the message. Do we need to
                        // re-init a handshake?
                        continue;
                    };

                    let Ok(decrypted_message) =
                        incoming_payload(&mut crypto_state, payload.to_vec())
                    else {
                        // If decryption fails, we cannot process the message. Do we need to log?
                        continue;
                    };

                    return Ok(IncomingMessage {
                        payload: decrypted_message,
                        destination: message.destination,
                        source: message.source,
                        topic: message.topic,
                    });
                }
                BitwardenNoiseFrame::NoiseHandshakeFinish { payload: _ } => {
                    // Handshake finish is handled in `connect`
                }
            }
        }
    }
}

async fn connect<Com: CommunicationBackend>(
    communication: &Com,
    destination: Endpoint,
) -> Result<NoiseCryptoProviderState, HandshakeError> {
    let receiver = communication.subscribe().await;

    let mut initiator = snow::Builder::new(
        CIPHER_SUITE
            .parse()
            .map_err(|_| HandshakeError::InvalidCipherSuite(CIPHER_SUITE.to_string()))?,
    )
    .build_initiator()
    .map_err(|_| HandshakeError::CryptoInitializationFailed)?;

    // Send handshake start message
    let handshake_start_message = OutgoingMessage {
        payload: BitwardenNoiseFrame::NoiseHandshakeStart {
            ciphersuite: CIPHER_SUITE.to_string(),
            payload: {
                let mut buffer = vec![0u8; 65536];
                let res = initiator
                    .write_message(&[], &mut buffer)
                    .expect("Writing message to buffer should not fail");
                buffer[..res].to_vec().into()
            },
        }
        .to_cbor(),
        destination,
        topic: None,
    };
    communication
        .send(handshake_start_message)
        .await
        .map_err(|_| HandshakeError::SendFailed)?;

    // Get handshake finish message
    let message = receiver
        .receive()
        .await
        .map_err(|_| HandshakeError::ReceiveFailed)?;
    let handshake_finish_frame = BitwardenNoiseFrame::from_cbor(&message.payload)
        .map_err(|_| HandshakeError::InvalidHandshakeFinish)?;
    let BitwardenNoiseFrame::NoiseHandshakeFinish { payload } = handshake_finish_frame else {
        return Err(HandshakeError::InvalidHandshakeFinish);
    };
    initiator
        .read_message(&payload, &mut Vec::new())
        .map_err(|_| HandshakeError::InvalidHandshakeFinish)?;

    // Convert to transport state. Note: i2r and r2i are mapped to send / receive keys,
    // so the order depends on whether this is the initiator or responder.
    let (i2r, r2i) = initiator.dangerously_get_raw_split();
    Ok(NoiseCryptoProviderState {
        state: PersistentTransportState::new(
            crate::crypto_provider::noise::persistent_transport_state::Cipher::ChaChaPoly,
            i2r,
            r2i,
        ),
    })
}

async fn incoming_handshake<Com: CommunicationBackend>(
    communication: &Com,
    cipher_suite: String,
    payload: Vec<u8>,
    endpoint: Endpoint,
) -> Result<NoiseCryptoProviderState, HandshakeError> {
    if cipher_suite != CIPHER_SUITE {
        return Err(HandshakeError::InvalidCipherSuite(cipher_suite));
    }

    // Construct a responder and read the message
    let mut handshake_state = snow::Builder::new(
        cipher_suite
            .parse()
            .map_err(|_| HandshakeError::InvalidCipherSuite(cipher_suite))?,
    )
    .build_responder()
    .map_err(|_| HandshakeError::CryptoInitializationFailed)?;
    handshake_state
        .read_message(&payload, &mut Vec::new())
        .map_err(|_| HandshakeError::InvalidHandshakeStart)?;

    // Respond with handshake finish message
    let handshake_finish_message = OutgoingMessage {
        payload: BitwardenNoiseFrame::NoiseHandshakeFinish {
            payload: {
                let mut buffer = vec![0u8; 65536];
                let res = handshake_state
                    .write_message(&[], &mut buffer)
                    .expect("Writing message to buffer should not fail");
                buffer[..res].to_vec().into()
            },
        }
        .to_cbor(),
        destination: endpoint,
        topic: None,
    };
    communication
        .send(handshake_finish_message)
        .await
        .map_err(|_| HandshakeError::SendFailed)?;

    // Convert to transport state. Note: i2r and r2i are mapped to send / receive keys, so
    // the order depends on whether this is the initiator or responder.
    let (i2r, r2i) = handshake_state.dangerously_get_raw_split();
    Ok(NoiseCryptoProviderState {
        state: PersistentTransportState::new(
            crate::crypto_provider::noise::persistent_transport_state::Cipher::ChaChaPoly,
            r2i,
            i2r,
        ),
    })
}

async fn send_payload(
    communication: &impl CommunicationBackend,
    crypto_state: &mut NoiseCryptoProviderState,
    message: OutgoingMessage,
) -> Result<(), PayloadError> {
    let buffer = crypto_state.state.write_message(&message.payload);
    communication
        .send(OutgoingMessage {
            payload: BitwardenNoiseFrame::NoiseTransportMessage {
                payload: buffer.to_cbor().into(),
            }
            .to_cbor(),
            destination: message.destination,
            topic: message.topic,
        })
        .await
        .map_err(|_| PayloadError::SendFailed)
}

fn incoming_payload(
    state: &mut NoiseCryptoProviderState,
    payload: Vec<u8>,
) -> Result<Vec<u8>, PayloadError> {
    let message = state
        .state
        .read_message(
            &TransportMessage::from_cbor(&payload).map_err(|_| PayloadError::DecryptionFailed)?,
        )
        .map_err(|_| PayloadError::DecryptionFailed)?;
    Ok(message)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{
        IpcClient,
        crypto_provider::noise::protocol::NoiseCryptoProvider,
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

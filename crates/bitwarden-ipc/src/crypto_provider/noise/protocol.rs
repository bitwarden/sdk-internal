use std::{sync::Arc, vec};

use snow::TransportState;
use tokio::sync::Mutex;

use crate::{
    crypto_provider::noise::{
        error::{HandshakeError, PayloadError},
        messages::BitwardenNoiseFrame,
    },
    endpoint::Endpoint,
    message::{IncomingMessage, OutgoingMessage},
    traits::{
        CommunicationBackend, CommunicationBackendReceiver, CryptoProvider, SessionRepository,
    },
};

#[allow(unused)]
const CIPHER_SUITE: &str = "Noise_NN_25519_ChaChaPoly_BLAKE2s";

#[allow(unused)]
struct NoiseCryptoProvider;
#[allow(unused)]
#[derive(Clone, Debug)]
struct NoiseCryptoProviderState {
    state: Arc<Mutex<Option<TransportState>>>,
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
        let crypto_state = if let Some(crypto_state) = crypto_state {
            crypto_state
        } else {
            // Should failing to connect be an error?
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
        if let Err(e) = send_payload(communication, &crypto_state, message).await {
            log::error!("[IPC send] Failed to send message: {e:?}");
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
                BitwardenNoiseFrame::HandshakeStart {
                    ciphersuite,
                    payload,
                } => {
                    // Do we need to stop if there is already a valid session?

                    let state = incoming_handshake(
                        communication,
                        ciphersuite,
                        payload.to_vec(),
                        message.source,
                    )
                    .await;
                    let Ok(state) = state else {
                        log::error!("[IPC receive] Handshake failed");
                        continue;
                    };

                    sessions
                        .save(message.source, state)
                        .await
                        .expect("Save session should not fail");
                }
                BitwardenNoiseFrame::Payload { payload } => {
                    let crypto_state = sessions
                        .get(message.source)
                        .await
                        .expect("Get session should not fail");
                    let Some(crypto_state) = crypto_state else {
                        // If no session exists, we cannot decrypt the message. Do we need to
                        // re-init a handshake?
                        continue;
                    };

                    let Ok(decrypted_message) =
                        incoming_payload(&crypto_state, payload.to_vec()).await
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
                BitwardenNoiseFrame::HandshakeFinish { payload: _ } => {
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
        payload: BitwardenNoiseFrame::HandshakeStart {
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
    let BitwardenNoiseFrame::HandshakeFinish { payload } = handshake_finish_frame else {
        return Err(HandshakeError::InvalidHandshakeFinish);
    };
    initiator
        .read_message(&payload, &mut Vec::new())
        .map_err(|_| HandshakeError::InvalidHandshakeFinish)?;

    log::debug!(
        "[Initiator] Handshake finished with hash: {}",
        hex::encode(initiator.get_handshake_hash())
    );

    // Setup state
    let transport_state = initiator
        .into_transport_mode()
        .map_err(|_| HandshakeError::CryptoInitializationFailed)?;
    Ok(NoiseCryptoProviderState {
        state: Arc::new(Mutex::new(Some(transport_state))),
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

    let state = NoiseCryptoProviderState {
        state: Arc::new(Mutex::new(None)),
    };

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

    log::debug!(
        "[Responder] Handshake finished with hash: {}",
        hex::encode(handshake_state.get_handshake_hash())
    );

    let handshake_finish_message = OutgoingMessage {
        payload: BitwardenNoiseFrame::HandshakeFinish {
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

    let transport_state = handshake_state
        .into_transport_mode()
        .map_err(|_| HandshakeError::CryptoInitializationFailed)?;
    state.state.lock().await.replace(transport_state);
    Ok(state)
}

async fn send_payload(
    communication: &impl CommunicationBackend,
    crypto_state: &NoiseCryptoProviderState,
    message: OutgoingMessage,
) -> Result<(), PayloadError> {
    let mut transport_state = crypto_state.state.lock().await;
    let transport_state = transport_state
        .as_mut()
        .ok_or(PayloadError::CryptoUninitialized)?;

    let mut buffer = vec![0u8; 65536];
    let res = transport_state
        .write_message(&message.payload, &mut buffer)
        .expect("Writing message to buffer should not fail");
    communication
        .send(OutgoingMessage {
            payload: BitwardenNoiseFrame::Payload {
                payload: buffer[..res].to_vec().into(),
            }
            .to_cbor(),
            destination: message.destination,
            topic: message.topic,
        })
        .await
        .map_err(|_| PayloadError::SendFailed)
}

async fn incoming_payload(
    state: &NoiseCryptoProviderState,
    payload: Vec<u8>,
) -> Result<Vec<u8>, PayloadError> {
    let mut transport_state = state.state.lock().await;
    let transport_state = transport_state
        .as_mut()
        .ok_or(PayloadError::CryptoUninitialized)?;
    let mut message = vec![0u8; 65536];
    let len = transport_state
        .read_message(&payload, &mut message)
        .map_err(|_| PayloadError::DecryptionFailed)?;
    message.truncate(len);
    Ok(message)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{
        crypto_provider::noise::protocol::NoiseCryptoProvider,
        endpoint::Endpoint,
        message::OutgoingMessage,
        traits::{tests::TestTwoWayCommunicationBackend, InMemorySessionRepository},
        IpcClient,
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

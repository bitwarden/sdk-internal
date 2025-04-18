use core::panic;
use std::{
    sync::{Arc, Mutex},
    vec,
};

use serde::{Deserialize, Serialize};
use snow::TransportState;

use super::{CommunicationBackend, CryptoProvider, SessionRepository};
use crate::{
    error::{ReceiveError, SendError},
    message::{IncomingMessage, OutgoingMessage},
};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
enum BitwardenCryptoProtocolIdentifier {
    Noise,
}

/// The Bitwarden IPC protocol is can have different crypto protocols.
/// Currently there is exactly one - Noise - implemented.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct BitwardenIpcCryptoProtocolFrame {
    protocol_identifier: BitwardenCryptoProtocolIdentifier,
    protocol_frame: Vec<u8>,
}

impl BitwardenIpcCryptoProtocolFrame {
    fn as_cbor(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        ciborium::into_writer(self, &mut buffer).unwrap();
        buffer
    }

    fn from_cbor(buffer: &[u8]) -> Self {
        ciborium::from_reader(buffer).unwrap()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum BitwardenNoiseFrame {
    HandshakeStart {
        ciphersuite: String,
        payload: Vec<u8>,
    },
    HandshakeFinish {
        payload: Vec<u8>,
    },
    Payload {
        payload: Vec<u8>,
    },
}

impl BitwardenNoiseFrame {
    fn as_cbor(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        ciborium::into_writer(self, &mut buffer).unwrap();
        buffer
    }

    fn from_cbor(buffer: &[u8]) -> Self {
        ciborium::from_reader(buffer).unwrap()
    }

    fn to_crypto_protocol_frame(&self) -> BitwardenIpcCryptoProtocolFrame {
        BitwardenIpcCryptoProtocolFrame {
            protocol_identifier: BitwardenCryptoProtocolIdentifier::Noise,
            protocol_frame: self.as_cbor(),
        }
    }
}

pub struct NoiseCryptoProvider;
#[derive(Clone, Debug)]
pub struct NoiseCryptoProviderState {
    state: Arc<Mutex<Option<TransportState>>>,
}

impl<Com, Ses> CryptoProvider<Com, Ses> for NoiseCryptoProvider
where
    Com: CommunicationBackend,
    Ses: SessionRepository<Session = NoiseCryptoProviderState>,
{
    type Session = NoiseCryptoProviderState;
    type SendError = Com::SendError;
    type ReceiveError = Com::ReceiveError;

    async fn send(
        &self,
        communication: &Com,
        sessions: &Ses,
        message: OutgoingMessage,
    ) -> Result<(), SendError<Self::SendError, Com::SendError>> {
        let Ok(crypto_state_opt) = sessions.get(message.destination.clone()).await else {
            panic!("Session not found");
        };
        let crypto_state = match crypto_state_opt {
            Some(state) => state,
            None => {
                let new_state = NoiseCryptoProviderState {
                    state: Arc::new(Mutex::new(None)),
                };
                sessions
                    .save(message.destination.clone(), new_state.clone())
                    .await;
                new_state
            }
        };

        // Session is not established yet. Establish it.
        if crypto_state.state.lock().unwrap().is_none() {
            let cipher_suite = "Noise_NN_25519_ChaChaPoly_BLAKE2s";
            let mut initiator = snow::Builder::new(cipher_suite.parse().unwrap())
                .build_initiator()
                .unwrap();

            // Send Handshake One
            let handshake_start_message = OutgoingMessage {
                payload: BitwardenNoiseFrame::HandshakeStart {
                    ciphersuite: cipher_suite.to_string(),
                    payload: {
                        let mut buffer = vec![0u8; 65536];
                        let res = initiator.write_message(&[], &mut buffer).unwrap();
                        buffer[..res].to_vec()
                    },
                }
                .to_crypto_protocol_frame()
                .as_cbor(),
                destination: message.destination.clone(),
                topic: None,
            };
            communication
                .send(handshake_start_message)
                .await
                .map_err(SendError::Communication)?;

            // Receive Handshake Two
            let handshake_finish_frame = communication
                .receive()
                .await
                .map_err(|_| SendError::ReceiveError)
                .map(|message| {
                    BitwardenIpcCryptoProtocolFrame::from_cbor(message.payload.as_slice())
                })
                .map(|frame| {
                    BitwardenNoiseFrame::from_cbor(frame.protocol_frame.as_slice())
                })?;
            let BitwardenNoiseFrame::HandshakeFinish { payload } = handshake_finish_frame else {
                panic!("Expected Handshake Two");
            };
            initiator.read_message(&payload, &mut Vec::new()).unwrap();

            let transport_state = initiator.into_transport_mode().unwrap();
            let mut state = crypto_state.state.lock().unwrap();
            *state = Some(transport_state);
        }

        // Send the payload
        let payload_message = OutgoingMessage {
            payload: BitwardenNoiseFrame::Payload {
                payload: {
                    let mut transport_state = crypto_state.state.lock().unwrap();
                    let transport_state = transport_state.as_mut().unwrap();
                    let mut buf = vec![0u8; 65536];
                    let len = transport_state
                        .write_message(message.payload.as_slice(), &mut buf)
                        .unwrap();
                    buf = buf[..len].to_vec();
                    println!("Send payload: {:?}", buf);
                    buf
                }
            }
                .to_crypto_protocol_frame()
                .as_cbor(),
            destination: message.destination.clone(),
            topic: message.topic,
        };
        communication
            .send(payload_message)
            .await
            .map_err(SendError::Communication)?;

        return Ok(());
    }

    async fn receive(
        &self,
        communication: &Com,
        sessions: &Ses,
    ) -> Result<IncomingMessage, ReceiveError<Self::ReceiveError, Com::ReceiveError>> {
        let mut message = communication
            .receive()
            .await
            .map_err(ReceiveError::Communication)?;
        let Ok(crypto_state_opt) = sessions.get(message.destination.clone()).await else {
            panic!("Session not found");
        };
        let crypto_state = match crypto_state_opt {
            Some(state) => state,
            None => {
                let new_state = NoiseCryptoProviderState {
                    state: Arc::new(Mutex::new(None)),
                };
                sessions
                    .save(message.destination.clone(), new_state.clone())
                    .await;
                new_state
            }
        };

        let crypto_protocol_frame = BitwardenIpcCryptoProtocolFrame::from_cbor(&message.payload);
        if crypto_protocol_frame.protocol_identifier
            != BitwardenCryptoProtocolIdentifier::Noise
        {
            panic!("Invalid protocol identifier");
        }

        // Check if session is established
       if crypto_state.state.lock().unwrap().is_none() {
            let protocol_frame =
                BitwardenNoiseFrame::from_cbor(crypto_protocol_frame.protocol_frame.as_slice());
            match protocol_frame {
                BitwardenNoiseFrame::HandshakeStart { ciphersuite, payload } => {
                    let supported_ciphersuite = "Noise_NN_25519_ChaChaPoly_BLAKE2s";
                    let mut responder = if ciphersuite == supported_ciphersuite {
                        snow::Builder::new(supported_ciphersuite.parse().unwrap())
                            .build_responder()
                            .unwrap()
                    } else {
                        panic!("Invalid protocol params");
                    };

                    responder
                        .read_message(payload.as_slice(), &mut Vec::new())
                        .unwrap();

                    let handshake_finish_message = OutgoingMessage {
                        payload: BitwardenNoiseFrame::HandshakeFinish {
                            payload: {
                                let mut buffer = vec![0u8; 65536];
                                let res = responder.write_message(&[], &mut buffer).unwrap();
                                buffer[..res].to_vec()
                            }
                        }.to_crypto_protocol_frame().as_cbor(),
                        destination: message.destination.clone(),
                        topic: None,
                    };
                    let res = communication.send(handshake_finish_message).await;
                    {
                        let mut transport_state = crypto_state.state.lock().unwrap();
                        *transport_state = Some(responder.into_transport_mode().unwrap());
                    }

                    message = communication.receive().await.map_err(|e| {
                        ReceiveError::Communication(e)
                    })?;
                }
                _ => {
                    panic!("Invalid protocol frame");
                }
            }
        }
        // Session is established. Read the payload.
        let crypto_protocol_frame = BitwardenIpcCryptoProtocolFrame::from_cbor(&message.payload);
        let protocol_frame = BitwardenNoiseFrame::from_cbor(
            crypto_protocol_frame.protocol_frame.as_slice(),
        );
        let BitwardenNoiseFrame::Payload { payload } = protocol_frame else {
            panic!("Expected Payload");
        };

        let mut transport_state = crypto_state.state.lock().unwrap();
        let transport_state = transport_state.as_mut().unwrap();
        return Ok(IncomingMessage {
            payload: {
                let mut buf = vec![0u8; 65536];
                let len = transport_state.read_message(payload.as_slice(), &mut buf).unwrap();
                buf[..len].to_vec()
            },
            destination: message.destination.clone(),
            source: message.source.clone(),
            topic: message.topic,
        });
    }
}

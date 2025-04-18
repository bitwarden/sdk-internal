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
        #[allow(clippy::unwrap_used)]
        ciborium::into_writer(self, &mut buffer).unwrap();
        buffer
    }

    fn from_cbor(buffer: &[u8]) -> Result<Self, ()> {
        ciborium::from_reader(buffer).map_err(|_| ())
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
        #[allow(clippy::unwrap_used)]
        ciborium::into_writer(self, &mut buffer).unwrap();
        buffer
    }

    fn from_cbor(buffer: &[u8]) -> Result<Self, ()> {
        ciborium::from_reader(buffer).map_err(|_| ())
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
        let Ok(crypto_state_opt) = sessions.get(message.destination).await else {
            panic!("Session not found");
        };
        let crypto_state = match crypto_state_opt {
            Some(state) => state,
            None => {
                let new_state = NoiseCryptoProviderState {
                    state: Arc::new(Mutex::new(None)),
                };
                // todo
                sessions
                    .save(message.destination, new_state.clone())
                    .await
                    .map_err(|_| SendError::HandshakeError)?;
                new_state
            }
        };

        // Session is not established yet. Establish it.
        #[allow(clippy::unwrap_used)]
        if crypto_state.state.lock().unwrap().is_none() {
            let cipher_suite = "Noise_NN_25519_ChaChaPoly_BLAKE2s";
            let mut initiator = snow::Builder::new(
                cipher_suite
                    .parse()
                    .map_err(|_| SendError::HandshakeError)?,
            )
            .build_initiator()
            .unwrap();

            // Send Handshake One
            let handshake_start_message = OutgoingMessage {
                payload: BitwardenNoiseFrame::HandshakeStart {
                    ciphersuite: cipher_suite.to_string(),
                    payload: {
                        let mut buffer = vec![0u8; 65536];
                        let res = initiator
                            .write_message(&[], &mut buffer)
                            .map_err(|_| SendError::HandshakeError)?;
                        buffer[..res].to_vec()
                    },
                }
                .to_crypto_protocol_frame()
                .as_cbor(),
                destination: message.destination,
                topic: None,
            };
            communication
                .send(handshake_start_message)
                .await
                .map_err(SendError::Communication)?;

            // Receive Handshake Two
            let message = communication
                .receive()
                .await
                .map_err(|_| SendError::HandshakeError)?;
            let frame = BitwardenIpcCryptoProtocolFrame::from_cbor(&message.payload)
                .map_err(|_| SendError::HandshakeError)?;
            let handshake_finish_frame =
                BitwardenNoiseFrame::from_cbor(frame.protocol_frame.as_slice())
                    .map_err(|_| SendError::HandshakeError)?;
            let BitwardenNoiseFrame::HandshakeFinish { payload } = handshake_finish_frame else {
                panic!("Expected Handshake Two");
            };
            initiator
                .read_message(&payload, &mut Vec::new())
                .map_err(|_| SendError::HandshakeError)?;

            let transport_state = initiator
                .into_transport_mode()
                .map_err(|_| SendError::HandshakeError)?;
            let mut state = crypto_state
                .state
                .lock()
                .map_err(|_| SendError::HandshakeError)?;
            *state = Some(transport_state);
        }

        // Send the payload
        let payload_message = OutgoingMessage {
            payload: BitwardenNoiseFrame::Payload {
                payload: {
                    #[allow(clippy::unwrap_used)]
                    let mut transport_state = crypto_state.state.lock().unwrap();
                    // todo error type
                    let transport_state =
                        transport_state.as_mut().ok_or(SendError::HandshakeError)?;
                    let mut buf = vec![0u8; 65536];
                    let len = transport_state
                        .write_message(message.payload.as_slice(), &mut buf)
                        .map_err(|_| SendError::HandshakeError)?;
                    buf = buf[..len].to_vec();
                    println!("Send payload: {:?}", buf);
                    buf
                },
            }
            .to_crypto_protocol_frame()
            .as_cbor(),
            destination: message.destination,
            topic: message.topic,
        };
        communication
            .send(payload_message)
            .await
            .map_err(SendError::Communication)?;

        Ok(())
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
        let Ok(crypto_state_opt) = sessions.get(message.destination).await else {
            panic!("Session not found");
        };
        let crypto_state = match crypto_state_opt {
            Some(state) => state,
            None => {
                let new_state = NoiseCryptoProviderState {
                    state: Arc::new(Mutex::new(None)),
                };
                sessions
                    .save(message.destination, new_state.clone())
                    .await
                    // todo
                    .map_err(|_| ReceiveError::HandshakeError)?;
                new_state
            }
        };

        let crypto_protocol_frame = BitwardenIpcCryptoProtocolFrame::from_cbor(&message.payload)
            .map_err(|_| ReceiveError::DecodeError)?;
        if crypto_protocol_frame.protocol_identifier != BitwardenCryptoProtocolIdentifier::Noise {
            panic!("Invalid protocol identifier");
        }

        // Check if session is established
        #[allow(clippy::unwrap_used)]
        if crypto_state.state.lock().unwrap().is_none() {
            let protocol_frame =
                BitwardenNoiseFrame::from_cbor(crypto_protocol_frame.protocol_frame.as_slice())
                    .map_err(|_| ReceiveError::DecodeError)?;
            match protocol_frame {
                BitwardenNoiseFrame::HandshakeStart {
                    ciphersuite,
                    payload,
                } => {
                    let supported_ciphersuite = "Noise_NN_25519_ChaChaPoly_BLAKE2s";
                    let mut responder = if ciphersuite == supported_ciphersuite {
                        snow::Builder::new(
                            supported_ciphersuite
                                .parse()
                                .map_err(|_| ReceiveError::HandshakeError)?,
                        )
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
                                let res = responder
                                    .write_message(&[], &mut buffer)
                                    .map_err(|_| ReceiveError::HandshakeError)?;
                                buffer[..res].to_vec()
                            },
                        }
                        .to_crypto_protocol_frame()
                        .as_cbor(),
                        destination: message.destination,
                        topic: None,
                    };
                    communication
                        .send(handshake_finish_message)
                        .await
                        .map_err(|_| ReceiveError::HandshakeError)?;
                    {
                        let mut transport_state = crypto_state.state.lock().unwrap();
                        *transport_state = Some(
                            responder
                                .into_transport_mode()
                                .map_err(|_| ReceiveError::HandshakeError)?,
                        );
                    }

                    message = communication
                        .receive()
                        .await
                        .map_err(ReceiveError::Communication)?;
                }
                _ => {
                    panic!("Invalid protocol frame");
                }
            }
        }
        // Session is established. Read the payload.
        let crypto_protocol_frame = BitwardenIpcCryptoProtocolFrame::from_cbor(&message.payload)
            .map_err(|_| ReceiveError::DecodeError)?;
        let protocol_frame =
            BitwardenNoiseFrame::from_cbor(crypto_protocol_frame.protocol_frame.as_slice())
                .map_err(|_| ReceiveError::DecodeError)?;
        let BitwardenNoiseFrame::Payload { payload } = protocol_frame else {
            panic!("Expected Payload");
        };

        #[allow(clippy::unwrap_used)]
        let mut transport_state = crypto_state.state.lock().unwrap();
        #[allow(clippy::unwrap_used)]
        let transport_state = transport_state.as_mut().unwrap();
        Ok(IncomingMessage {
            payload: {
                let mut buf = vec![0u8; 65536];
                let len = transport_state
                    .read_message(payload.as_slice(), &mut buf)
                    .map_err(|_| ReceiveError::DecodeError)?;
                buf[..len].to_vec()
            },
            destination: message.destination,
            source: message.source,
            topic: message.topic,
        })
    }
}

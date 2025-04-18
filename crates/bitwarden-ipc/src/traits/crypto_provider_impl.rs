use core::panic;
use std::{sync::{Arc, Mutex}, vec};

use serde::{Deserialize, Serialize};
use snow::TransportState;

use crate::{error::{ReceiveError, SendError}, message::{IncomingMessage, OutgoingMessage}};

use super::{CommunicationBackend, CryptoProvider, SessionRepository};

#[derive(Clone, Debug, Deserialize, Serialize)]
enum BitwardenCryptoProtocolIdentifier {
    NoiseCbor,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct BitwardenCryptoProtocolFrame {
    protocol_identifier: BitwardenCryptoProtocolIdentifier,
    protocol_frame: Vec<u8>,
}

impl BitwardenCryptoProtocolFrame {
    fn noise_frame(frame: BitwardenNoiseFrame) -> Self {
        BitwardenCryptoProtocolFrame {
            protocol_identifier: BitwardenCryptoProtocolIdentifier::NoiseCbor,
            protocol_frame: frame.as_cbor(),
        }
    }

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
    HandshakeOne {
        params: String,
        payload: Vec<u8>,
    },
    HandshakeTwo {
        payload: Vec<u8>,
    },
    HandshakeThree {
        payload: Vec<u8>,
    },
    Payload {
        payload: Vec<u8>,
    }
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
}

pub struct BitwardenCryptoProvider;
#[derive(Clone, Debug)]
pub struct NoiseCryptoProviderState {
    state: Arc<Mutex<Option<TransportState>>>,
}

impl <Com, Ses> CryptoProvider<Com, Ses> for BitwardenCryptoProvider
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
                let new_state = NoiseCryptoProviderState { state: Arc::new(Mutex::new(None)) };
                sessions.save(message.destination.clone(), new_state.clone()).await;
                new_state
            }
        };

        // Session is not established yet. Establish it.
        if crypto_state.state.lock().unwrap().is_none() {
            let mut initiator = snow::Builder::new("Noise_NN_25519_ChaChaPoly_BLAKE2s".parse().unwrap()).build_initiator().unwrap();

            // Send Handshake One
            let mut buffer = vec![0u8; 65536];
            let res = initiator.write_message(&[], &mut buffer).unwrap();
            buffer = buffer[..res].to_vec();
            println!("Handshake One: {:?}", res);
            let handshake_one = BitwardenNoiseFrame::HandshakeOne { params: "Noise_NN_25519_ChaChaPoly_BLAKE2s".to_string(), payload: buffer.to_vec() };
            let msg = OutgoingMessage {
                payload:  BitwardenCryptoProtocolFrame::noise_frame(handshake_one).as_cbor(),
                destination: message.destination.clone(),
                topic: None,
            };
            println!("Sending Handshake One: {:?}", msg);
            communication.send(msg).await.map_err(SendError::Communication)?;
            println!("Sent Handshake One");

            // sleep
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

            // Receive Handshake Two
            let mut buffer = Vec::new(); 
            println!("Waiting for Handshake Two");
            let resp = communication.receive().await.map_err(|_| SendError::ReceiveError)?;
            let handshake_two = BitwardenCryptoProtocolFrame::from_cbor(resp.payload.as_slice());
            let resp = BitwardenNoiseFrame::from_cbor(handshake_two.protocol_frame.as_slice());
            let BitwardenNoiseFrame::HandshakeTwo { payload } = resp else {
                panic!("Expected Handshake Two");
            };
            println!("Received Handshake Two: {:?}", &payload);
            initiator.read_message(&payload, &mut buffer).unwrap();
            println!("Parsed Handshake Two: {:?}", &buffer);

            // Transport Mode
            let sess = initiator.into_transport_mode().unwrap();
            let mut state = crypto_state.state.lock().unwrap();
            *state = Some(sess);
        }

        let buf = {
            let mut sess = crypto_state.state.lock().unwrap();
            let sess = sess.as_mut().unwrap();
            let mut buf = vec![0u8; 65536];
            let len = sess.write_message(message.payload.as_slice(), &mut buf).unwrap();
            buf = buf[..len].to_vec();
            buf
        };

        let msg = OutgoingMessage {
            payload: BitwardenCryptoProtocolFrame::noise_frame(BitwardenNoiseFrame::Payload { payload: buf }).as_cbor(),
            destination: message.destination.clone(),
            topic: message.topic,
        };
        println!("Sending payload: {:?}", msg);
        communication.send(msg).await.map_err(SendError::Communication)?;

        return Ok(());
    }

    async fn receive(
        &self,
        communication: &Com,
        sessions: &Ses,
    ) -> Result<IncomingMessage, ReceiveError<Self::ReceiveError, Com::ReceiveError>> {
        let message = communication
            .receive()
            .await
            .map_err(ReceiveError::Communication)?;
        let Ok(crypto_state_opt) = sessions.get(message.destination.clone()).await else {
            panic!("Session not found");
        };
        let crypto_state = match crypto_state_opt {
            Some(state) => state,
            None => {
                let new_state = NoiseCryptoProviderState { state: Arc::new(Mutex::new(None)) };
                sessions.save(message.destination.clone(), new_state.clone()).await;
                new_state
            }
        };

        let payload = message.payload;
        println!("Received payload: {:?}", payload);
        let crypto_protocol_frame: BitwardenCryptoProtocolFrame = ciborium::from_reader(payload.as_slice()).unwrap();
        match crypto_protocol_frame.protocol_identifier {
            BitwardenCryptoProtocolIdentifier::NoiseCbor => {
                let protocol_frame = BitwardenNoiseFrame::from_cbor(crypto_protocol_frame.protocol_frame.as_slice());
                match protocol_frame {
                    BitwardenNoiseFrame::HandshakeOne { params, payload } => {
                        let mut responder = if params == "Noise_NN_25519_ChaChaPoly_BLAKE2s" {
                            snow::Builder::new("Noise_NN_25519_ChaChaPoly_BLAKE2s".parse().unwrap()).build_responder().unwrap()
                        } else {
                            panic!("Invalid protocol params");
                        };
                        let mut buffer = vec![0u8; 65536];
                        responder.read_message(payload.as_slice(), &mut buffer).unwrap();
                        
                        let res = responder.write_message(&[], &mut buffer).unwrap();
                        buffer = buffer[..res].to_vec();
                        println!("Handshake Two: {:?}", res);
                        let handshake_two = BitwardenNoiseFrame::HandshakeTwo { payload: buffer.to_vec() };
                        let msg = OutgoingMessage {
                            payload: BitwardenCryptoProtocolFrame::noise_frame(handshake_two).as_cbor(),
                            destination: message.destination.clone(),
                            topic: None,
                        };
                        println!("Sending Handshake Two: {:?}", msg);
                        let res = communication.send(msg).await;
                        println!("Sent Handshake Two");
                        
                        {
                            let mut state = crypto_state.state.lock().unwrap();
                            *state = Some(responder.into_transport_mode().unwrap());
                            println!("Recv Handshake complete");
                        }


                        let payload = communication.receive().await.map_err(ReceiveError::Communication)?;
                        let crypto_protocol_frame: BitwardenCryptoProtocolFrame = ciborium::from_reader(payload.payload.as_slice()).unwrap();
                        let protocol_frame = BitwardenNoiseFrame::from_cbor(crypto_protocol_frame.protocol_frame.as_slice());
                        let BitwardenNoiseFrame::Payload { payload } = protocol_frame else {
                            panic!("Expected Payload");
                        };

                        // read message
                        println!("Waiting for payload");
                        let mut buf = vec![0u8; 65536];
                        let mut sess = crypto_state.state.lock().unwrap();
                        let sess = sess.as_mut().unwrap();
                        let len = sess.read_message(payload.as_slice(), &mut buf).unwrap();
                        buf = buf[..len].to_vec();
                        println!("Parsed payload: {:?}", &buf);
                        return Ok(IncomingMessage {
                            payload: buf,
                            destination: message.destination.clone(),
                            source: message.source.clone(),
                            topic: message.topic,
                        });
                    },
                    BitwardenNoiseFrame::Payload { payload } => {
                        let mut buf = vec![0u8; 65536];
                        let mut sess = crypto_state.state.lock().unwrap();
                        let sess = sess.as_mut().unwrap();
                        let len = sess.read_message(payload.as_slice(), &mut buf).unwrap();
                        buf = buf[..len].to_vec();
                        println!("Parsed payload: {:?}", &buf);
                        return Ok(IncomingMessage {
                            payload: buf,
                            destination: message.destination.clone(),
                            source: message.source.clone(),
                            topic: message.topic,
                        });
                    },
                    _ => {
                        panic!("Invalid protocol frame");
                    }
                }
            },
            _ => {
                todo!()
            }
        };
        todo!();
    }
}

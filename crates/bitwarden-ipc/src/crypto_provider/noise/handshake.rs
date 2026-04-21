//! This module implements the Noise NN handshake for IPC.
//! Note: NN does not provide any sort of authentication, and the keys each
//! side uses are just trusted. This means that a MITM with active tampering is possible and
//! accepted. Thereby it is necessary that either the threat model of the application using IPC
//! assumes that the IPC channel is not exposed to MITM attacks, or that the transport layer
//! prevents MITM with active tampering.
//!
//! Protocol flow:
//! 1. Initiator -> Responder: `HandshakeStartMessage { ciphersuite, noise_frame }`
//! 2. Responder -> Initiator: `HandshakeFinishMessage { noise_frame }`
//!
//! After both messages are processed, each side derives split transport keys from the
//! handshake state and constructs a `PersistentTransportState`.

use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

use crate::crypto_provider::noise::transport_state::{
    PersistentTransportState, SymmetricKey, TransportCipher,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) enum CipherSuite {
    #[allow(non_camel_case_types)]
    Noise_NN_25519_ChaChaPoly_BLAKE2s,
    #[allow(non_camel_case_types)]
    Noise_NN_25519_AESGCM_SHA256,
}

impl Default for CipherSuite {
    fn default() -> Self {
        if cfg!(feature = "fips") {
            Self::Noise_NN_25519_AESGCM_SHA256
        } else {
            Self::Noise_NN_25519_ChaChaPoly_BLAKE2s
        }
    }
}

impl CipherSuite {
    /// Returns the transport cipher corresponding to this cipher suite.
    pub(crate) fn transport_cipher(&self) -> TransportCipher {
        match self {
            Self::Noise_NN_25519_ChaChaPoly_BLAKE2s => TransportCipher::ChaCha20Poly1305,
            Self::Noise_NN_25519_AESGCM_SHA256 => TransportCipher::Aes256Gcm,
        }
    }
}

impl Display for CipherSuite {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Noise_NN_25519_ChaChaPoly_BLAKE2s => {
                write!(f, "Noise_NN_25519_ChaChaPoly_BLAKE2s")
            }
            Self::Noise_NN_25519_AESGCM_SHA256 => {
                write!(f, "Noise_NN_25519_AESGCM_SHA256")
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HandshakeStartMessage {
    pub(super) ciphersuite: CipherSuite,
    pub(super) noise_frame: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct HandshakeFinishMessage {
    pub(super) noise_frame: Vec<u8>,
}

pub(crate) struct HandshakeInitiator {
    ciphersuite: CipherSuite,
    state: snow::HandshakeState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WriteError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReadError;

impl HandshakeInitiator {
    pub(crate) fn new(ciphersuite: &CipherSuite) -> Self {
        let builder = snow::Builder::new(
            ciphersuite
                .to_string()
                .parse()
                .expect("Ciphersuite should be valid"),
        );
        let handshake_state = builder
            .build_initiator()
            .expect("Handshake state should be buildable");
        Self {
            ciphersuite: *ciphersuite,
            state: handshake_state,
        }
    }

    pub(crate) fn write_start_message(&mut self) -> Result<HandshakeStartMessage, WriteError> {
        let mut buf = [0u8; super::NOISE_MAX_MESSAGE_LEN];
        let len = self
            .state
            .write_message(&[], &mut buf)
            .map_err(|_| WriteError)?;
        Ok(HandshakeStartMessage {
            ciphersuite: self.ciphersuite,
            noise_frame: buf[..len].to_vec(),
        })
    }

    pub(crate) fn read_response_message(
        &mut self,
        message: &HandshakeFinishMessage,
    ) -> Result<(), ReadError> {
        let mut buf = [0u8; super::NOISE_MAX_MESSAGE_LEN];
        self.state
            .read_message(&message.noise_frame, &mut buf)
            .map_err(|_| ReadError)?;
        Ok(())
    }
}

impl From<&mut HandshakeInitiator> for PersistentTransportState {
    fn from(initiator: &mut HandshakeInitiator) -> Self {
        let (i2r, r2i) = initiator.state.dangerously_get_raw_split();
        PersistentTransportState::new(
            SymmetricKey(i2r),
            SymmetricKey(r2i),
            initiator.ciphersuite.transport_cipher(),
        )
    }
}

pub(crate) struct HandshakeResponder {
    ciphersuite: CipherSuite,
    state: snow::HandshakeState,
}

impl HandshakeResponder {
    pub(crate) fn new(ciphersuite: &CipherSuite) -> Self {
        let builder = snow::Builder::new(
            ciphersuite
                .to_string()
                .parse()
                .expect("Ciphersuite should be valid"),
        );
        let handshake_state = builder
            .build_responder()
            .expect("Handshake state should be buildable");
        Self {
            ciphersuite: *ciphersuite,
            state: handshake_state,
        }
    }

    pub(crate) fn read_start_message(
        &mut self,
        message: &HandshakeStartMessage,
    ) -> Result<(), ReadError> {
        let mut buf = [0u8; super::NOISE_MAX_MESSAGE_LEN];
        self.state
            .read_message(&message.noise_frame, &mut buf)
            .map_err(|_| ReadError)?;
        Ok(())
    }

    pub(crate) fn write_response_message(&mut self) -> Result<HandshakeFinishMessage, WriteError> {
        let mut buf = [0u8; super::NOISE_MAX_MESSAGE_LEN];
        let len = self
            .state
            .write_message(&[], &mut buf)
            .map_err(|_| WriteError)?;
        Ok(HandshakeFinishMessage {
            noise_frame: buf[..len].to_vec(),
        })
    }
}

impl From<&mut HandshakeResponder> for PersistentTransportState {
    fn from(responder: &mut HandshakeResponder) -> Self {
        let (i2r, r2i) = responder.state.dangerously_get_raw_split();
        PersistentTransportState::new(
            SymmetricKey(r2i),
            SymmetricKey(i2r),
            responder.ciphersuite.transport_cipher(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_provider::noise::transport_state::assert_matching_pair;

    #[test]
    fn test_handshake() {
        let mut initiator = HandshakeInitiator::new(&CipherSuite::default());
        let mut responder = HandshakeResponder::new(&CipherSuite::default());

        let init_message = initiator.write_start_message().unwrap();
        responder.read_start_message(&init_message).unwrap();
        let response_message = responder.write_response_message().unwrap();
        initiator.read_response_message(&response_message).unwrap();

        let initiator_transport_state = (&mut initiator).into();
        let responder_transport_state = (&mut responder).into();
        assert_matching_pair(&initiator_transport_state, &responder_transport_state);
    }
}

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
    PersistentTransportState, SessionId, SymmetricKey, TransportCipher,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub(crate) enum CipherSuite {
    #[allow(non_camel_case_types)]
    Noise_NN_25519_ChaChaPoly_BLAKE2s,
    #[allow(non_camel_case_types)]
    Noise_NN_25519_AESGCM_SHA256,
    #[allow(non_camel_case_types)]
    #[default]
    Noise_NN_P256_AESGCM_SHA256,
}

impl CipherSuite {
    /// Returns the transport cipher corresponding to this cipher suite.
    pub(crate) fn transport_cipher(&self) -> TransportCipher {
        match self {
            Self::Noise_NN_25519_ChaChaPoly_BLAKE2s => TransportCipher::ChaCha20Poly1305,
            Self::Noise_NN_25519_AESGCM_SHA256 => TransportCipher::Aes256Gcm,
            Self::Noise_NN_P256_AESGCM_SHA256 => TransportCipher::Aes256Gcm,
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
            Self::Noise_NN_P256_AESGCM_SHA256 => {
                write!(f, "Noise_NN_P256_AESGCM_SHA256")
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HandshakeStartMessage {
    pub(super) ciphersuite: CipherSuite,
    pub(super) noise_frame: Vec<u8>,
    // The session identifier decided by the initiator; the responder adopts it for the session
    // established by this handshake. `serde(default)` keeps start messages from peers that
    // predate this field parseable; they get the all-zero sentinel.
    #[serde(default)]
    pub(super) session_id: SessionId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct HandshakeFinishMessage {
    pub(super) noise_frame: Vec<u8>,
}

pub(crate) struct HandshakeInitiator {
    ciphersuite: CipherSuite,
    state: snow::HandshakeState,
    session_id: SessionId,
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
            // The initiator decides the identifier of the session this handshake establishes.
            session_id: SessionId::generate(),
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
            session_id: self.session_id.clone(),
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
            initiator.session_id.clone(),
        )
    }
}

pub(crate) struct HandshakeResponder {
    ciphersuite: CipherSuite,
    state: snow::HandshakeState,
    // The session identifier decided by the initiator, adopted from the handshake start message.
    session_id: Option<SessionId>,
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
            session_id: None,
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
        self.session_id = Some(message.session_id.clone());
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
        let session_id = responder
            .session_id
            .clone()
            .expect("The handshake start message has been read before deriving transport keys");
        let (i2r, r2i) = responder.state.dangerously_get_raw_split();
        PersistentTransportState::new(
            SymmetricKey(r2i),
            SymmetricKey(i2r),
            responder.ciphersuite.transport_cipher(),
            session_id,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_provider::noise::transport_state::assert_matching_pair;

    fn run_handshake(
        ciphersuite: &CipherSuite,
    ) -> (PersistentTransportState, PersistentTransportState) {
        let mut initiator = HandshakeInitiator::new(ciphersuite);
        let mut responder = HandshakeResponder::new(ciphersuite);

        let init_message = initiator.write_start_message().unwrap();
        responder.read_start_message(&init_message).unwrap();
        let response_message = responder.write_response_message().unwrap();
        initiator.read_response_message(&response_message).unwrap();

        let initiator_transport_state: PersistentTransportState = (&mut initiator).into();
        let responder_transport_state: PersistentTransportState = (&mut responder).into();
        assert_matching_pair(&initiator_transport_state, &responder_transport_state);
        (initiator_transport_state, responder_transport_state)
    }

    #[test]
    fn test_handshake() {
        for ciphersuite in [
            CipherSuite::Noise_NN_25519_ChaChaPoly_BLAKE2s,
            CipherSuite::Noise_NN_25519_AESGCM_SHA256,
            CipherSuite::Noise_NN_P256_AESGCM_SHA256,
        ] {
            run_handshake(&ciphersuite);
        }
    }

    #[test]
    fn test_distinct_handshakes_yield_distinct_session_ids() {
        let (first, _) = run_handshake(&CipherSuite::default());
        let (second, _) = run_handshake(&CipherSuite::default());

        assert_ne!(
            first.session_id(),
            second.session_id(),
            "each handshake must produce a unique session id"
        );
    }
}

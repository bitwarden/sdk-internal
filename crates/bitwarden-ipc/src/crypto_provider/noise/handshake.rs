use serde::{Deserialize, Serialize};

use crate::crypto_provider::noise::transport_state::{PersistentTransportState, SymmetricKey};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub(crate) enum CipherSuite {
    #[default]
    #[allow(non_camel_case_types)]
    Noise_NN_25519_ChaChaPoly_BLAKE2s,
}

impl CipherSuite {
    pub(crate) fn to_string(&self) -> String {
        match self {
            Self::Noise_NN_25519_ChaChaPoly_BLAKE2s => {
                "Noise_NN_25519_ChaChaPoly_BLAKE2s".to_string()
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
    cipher_suite: CipherSuite,
    state: snow::HandshakeState,
}

impl HandshakeInitiator {
    pub(crate) fn new(cipher_suite: &CipherSuite) -> Result<Self, ()> {
        let builder = snow::Builder::new(cipher_suite.to_string().parse().unwrap());
        let handshake_state = builder.build_initiator().unwrap();
        Ok(Self {
            cipher_suite: *cipher_suite,
            state: handshake_state,
        })
    }

    pub(crate) fn write_start_message(&mut self) -> Result<HandshakeStartMessage, ()> {
        let mut buf = [0u8; super::NOISE_MAX_MESSAGE_LEN];
        let len = self.state.write_message(&[], &mut buf).map_err(|_| ())?;
        Ok(HandshakeStartMessage {
            ciphersuite: self.cipher_suite,
            noise_frame: buf[..len].to_vec(),
        })
    }

    pub(crate) fn read_response_message(
        &mut self,
        message: &HandshakeFinishMessage,
    ) -> Result<(), ()> {
        let mut buf = [0u8; super::NOISE_MAX_MESSAGE_LEN];
        self.state
            .read_message(&message.noise_frame, &mut buf)
            .map_err(|_| ())?;
        Ok(())
    }
}

impl From<&mut HandshakeInitiator> for PersistentTransportState {
    fn from(initiator: &mut HandshakeInitiator) -> Self {
        let (i2r, r2i) = initiator.state.dangerously_get_raw_split();
        PersistentTransportState::new(SymmetricKey(r2i), SymmetricKey(i2r))
    }
}

pub(crate) struct HandshakeResponder {
    state: snow::HandshakeState,
}

impl HandshakeResponder {
    pub(crate) fn new(cipher_suite: &CipherSuite) -> Result<Self, ()> {
        let builder = snow::Builder::new(cipher_suite.to_string().parse().map_err(|_| ())?);
        let handshake_state = builder.build_responder().map_err(|_| ())?;
        Ok(Self {
            state: handshake_state,
        })
    }

    pub(crate) fn read_start_message(&mut self, message: &HandshakeStartMessage) -> Result<(), ()> {
        let mut buf = [0u8; super::NOISE_MAX_MESSAGE_LEN];
        self.state
            .read_message(&message.noise_frame, &mut buf)
            .map_err(|_| ())?;
        Ok(())
    }

    pub(crate) fn write_response_message(&mut self) -> Result<HandshakeFinishMessage, ()> {
        let mut buf = [0u8; super::NOISE_MAX_MESSAGE_LEN];
        let len = self.state.write_message(&[], &mut buf).map_err(|_| ())?;
        Ok(HandshakeFinishMessage {
            noise_frame: buf[..len].to_vec(),
        })
    }
}

impl From<&mut HandshakeResponder> for PersistentTransportState {
    fn from(responder: &mut HandshakeResponder) -> Self {
        let (i2r, r2i) = responder.state.dangerously_get_raw_split();
        PersistentTransportState::new(SymmetricKey(r2i), SymmetricKey(i2r))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_provider::noise::transport_state::assert_matching_pair;

    #[test]
    fn test_handshake() {
        let mut initiator = HandshakeInitiator::new(&CipherSuite::default()).unwrap();
        let mut responder = HandshakeResponder::new(&CipherSuite::default()).unwrap();

        let init_message = initiator.write_start_message().unwrap();
        responder.read_start_message(&init_message).unwrap();
        let response_message = responder.write_response_message().unwrap();
        initiator.read_response_message(&response_message).unwrap();

        let initiator_transport_state = (&mut initiator).into();
        let responder_transport_state = (&mut responder).into();
        assert_matching_pair(&initiator_transport_state, &responder_transport_state);
    }
}

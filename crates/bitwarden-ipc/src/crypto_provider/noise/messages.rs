use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

// Ignore because the names are part of the serialized
// representation.
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) enum BitwardenNoiseFrame {
    NoiseHandshakeStart {
        ciphersuite: String,
        payload: ByteBuf,
    },
    NoiseHandshakeFinish {
        payload: ByteBuf,
    },
    NoiseTransportMessage {
        payload: ByteBuf,
    },
}

impl BitwardenNoiseFrame {
    pub(super) fn to_cbor(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        ciborium::into_writer(self, &mut buffer).expect("Ciborium serialization should not fail");
        buffer
    }

    pub(super) fn from_cbor(buffer: &[u8]) -> Result<Self, ()> {
        ciborium::from_reader(buffer).map_err(|_| ())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct TransportMessage {
    pub(super) payload: ByteBuf,
    pub(super) nonce: u64,
    pub(super) rekey_counter: u64,
}

impl TransportMessage {
    pub(super) fn to_cbor(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        ciborium::into_writer(self, &mut buffer).expect("Ciborium serialization should not fail");
        buffer
    }

    pub(super) fn from_cbor(buffer: &[u8]) -> Result<Self, ()> {
        ciborium::from_reader(buffer).map_err(|_| ())
    }
}

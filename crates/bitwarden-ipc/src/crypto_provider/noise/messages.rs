use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) enum BitwardenNoiseFrame {
    HandshakeStart {
        ciphersuite: String,
        payload: ByteBuf,
    },
    HandshakeFinish {
        payload: ByteBuf,
    },
    Payload {
        payload: ByteBuf,
    },
}

#[allow(unused)]
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

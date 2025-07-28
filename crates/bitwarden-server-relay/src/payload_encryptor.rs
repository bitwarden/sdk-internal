use crate::messages::*;

pub(super) struct PayloadEncryptor {
    noise: snow::TransportState,
}

impl PayloadEncryptor {
    pub(crate) fn new(noise: snow::TransportState) -> Self {
        PayloadEncryptor { noise }
    }

    pub(crate) fn encrypt(&mut self, decrypted_message: ProtocolPayload) -> Vec<u8> {
        let mut serialized = Vec::new();
        ciborium::ser::into_writer(&decrypted_message, &mut serialized).unwrap();

        let mut buf = [0u8; 65535];
        let len = self.noise.write_message(&serialized, &mut buf).unwrap();
        buf[..len].to_vec()
    }

    pub(crate) fn decrypt(&mut self, encrypted_message: Vec<u8>) -> ProtocolPayload {
        let mut buf = [0u8; 65535];
        let len = self
            .noise
            .read_message(&encrypted_message, &mut buf)
            .unwrap();
        let decrypted = buf[..len].to_vec();
        ciborium::de::from_reader(&decrypted[..]).unwrap()
    }
}

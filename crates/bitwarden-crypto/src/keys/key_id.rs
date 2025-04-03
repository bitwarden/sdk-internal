use rand::RngCore;

pub(crate) struct KeyId([u8; 24]);

impl KeyId {
    pub fn as_bytes(&self) -> &[u8; 24] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; 24]) -> Self {
        KeyId(bytes)
    }

    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let mut key_id = [0u8; 24];
        rng.fill_bytes(&mut key_id);
        Self::from_bytes(key_id)
    }
}

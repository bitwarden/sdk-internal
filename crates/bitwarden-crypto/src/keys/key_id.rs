use rand::RngCore;

pub(crate) const KEY_ID_SIZE: usize = 16;

pub(crate) struct KeyId([u8; KEY_ID_SIZE]);

/// Fixed length identifiers for keys.
/// These are intended to be unique and constant per-key.
///
/// Currently these are randomly generated 16 byte identifiers, which is considered safe to randomly
/// generate with vanishingly small collision chance. However, the generation of IDs is an internal
/// concern and may change in the future.
impl KeyId {
    pub fn as_bytes(&self) -> &[u8; KEY_ID_SIZE] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; KEY_ID_SIZE]) -> Self {
        KeyId(bytes)
    }

    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let mut key_id = [0u8; KEY_ID_SIZE];
        rng.fill_bytes(&mut key_id);
        Self::from_bytes(key_id)
    }
}

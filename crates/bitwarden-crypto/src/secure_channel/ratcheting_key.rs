use serde::{Deserialize, Serialize};

use super::fingerprint::Fingerprint;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(super) struct RatchetingKey {
    key: [u8; 32],
}

impl RatchetingKey {
    pub(super) fn new(initial: [u8; 32]) -> Self {
        RatchetingKey { key: initial }
    }

    fn ratchet(&mut self) -> Self {
        let new_key: [u8; 32] =
            crate::blake3::hash_blake3_tuple(&[self.key.as_ref(), "ratchet".as_bytes()]);
        return RatchetingKey { key: new_key };
    }

    fn inner(&self) -> [u8; 32] {
        self.key
    }

    fn as_slice(&self) -> &[u8] {
        &self.key
    }

    fn into_iter(self) -> std::array::IntoIter<u8, 32> {
        self.key.into_iter()
    }
}

impl Fingerprint for RatchetingKey {
    fn fingerprint(&self) -> [u8; 32] {
        crate::blake3::hash_blake3_tuple(&[self.key.as_ref()])
    }
}

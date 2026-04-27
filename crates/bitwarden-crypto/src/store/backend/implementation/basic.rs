use zeroize::ZeroizeOnDrop;

use crate::{KeySlotId, store::backend::StoreBackend};

/// This is a basic key store backend that stores keys in a HashMap memory.
/// No protections are provided for the keys stored in this backend, beyond enforcing
/// zeroization on drop.
pub(crate) struct BasicBackend<Key: KeySlotId> {
    keys: std::collections::HashMap<Key, Key::KeyValue>,
}

impl<Key: KeySlotId> BasicBackend<Key> {
    pub fn new() -> Self {
        Self {
            keys: std::collections::HashMap::new(),
        }
    }
}

impl<Key: KeySlotId> StoreBackend<Key> for BasicBackend<Key> {
    fn upsert(&mut self, key_id: Key, key: <Key as KeySlotId>::KeyValue) {
        self.keys.insert(key_id, key);
    }

    fn get(&self, key_id: Key) -> Option<&<Key as KeySlotId>::KeyValue> {
        self.keys.get(&key_id)
    }

    fn remove(&mut self, key_id: Key) {
        self.keys.remove(&key_id);
    }

    fn clear(&mut self) {
        self.keys.clear();
    }

    fn retain(&mut self, f: fn(Key) -> bool) {
        self.keys.retain(|k, _| f(*k));
    }
}

/// [KeySlotId::KeyValue] already implements [ZeroizeOnDrop],
/// so we only need to ensure the map is cleared on drop.
impl<Key: KeySlotId> ZeroizeOnDrop for BasicBackend<Key> {}
impl<Key: KeySlotId> Drop for BasicBackend<Key> {
    fn drop(&mut self) {
        self.clear();
    }
}

use zeroize::ZeroizeOnDrop;

use crate::{store::backend::StoreBackend, KeyRef};

/// This is a basic key store backend that stores keys in a HashMap memory.
/// No protections are provided for the keys stored in this backend, beyond enforcing
/// zeroization on drop.
pub(crate) struct BasicBackend<Key: KeyRef> {
    keys: std::collections::HashMap<Key, Key::KeyValue>,
}

impl<Key: KeyRef> BasicBackend<Key> {
    pub fn new() -> Self {
        Self {
            keys: std::collections::HashMap::new(),
        }
    }
}

impl<Key: KeyRef> StoreBackend<Key> for BasicBackend<Key> {
    fn insert(&mut self, key_ref: Key, key: <Key as KeyRef>::KeyValue) {
        self.keys.insert(key_ref, key);
    }

    fn get(&self, key_ref: Key) -> Option<&<Key as KeyRef>::KeyValue> {
        self.keys.get(&key_ref)
    }

    fn remove(&mut self, key_ref: Key) {
        self.keys.remove(&key_ref);
    }

    fn clear(&mut self) {
        self.keys.clear();
    }

    fn retain(&mut self, f: fn(Key) -> bool) {
        self.keys.retain(|k, _| f(*k));
    }
}

// Key::KeyValue already implements ZeroizeOnDrop,
// so we only need to ensure the map is cleared on drop.
impl<Key: KeyRef> ZeroizeOnDrop for BasicBackend<Key> {}
impl<Key: KeyRef> Drop for BasicBackend<Key> {
    fn drop(&mut self) {
        self.clear();
    }
}

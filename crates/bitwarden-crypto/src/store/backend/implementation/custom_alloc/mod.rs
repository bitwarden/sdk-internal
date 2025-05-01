use allocator_api2::alloc::Allocator;
use zeroize::ZeroizeOnDrop;

use crate::{store::backend::StoreBackend, KeyId};

mod malloc;

pub(super) type MlockBackend<Key> = CustomAllocBackend<Key, malloc::MlockAlloc>;
pub(super) use malloc::MlockAlloc;

#[cfg(all(target_os = "linux", not(feature = "no-memory-hardening")))]
mod linux_memfd_secret;
#[cfg(all(target_os = "linux", not(feature = "no-memory-hardening")))]
pub(super) type LinuxMemfdSecretBackend<Key> =
    CustomAllocBackend<Key, linux_memfd_secret::LinuxMemfdSecretAlloc>;
#[cfg(all(target_os = "linux", not(feature = "no-memory-hardening")))]
pub(super) use linux_memfd_secret::LinuxMemfdSecretAlloc;

pub(super) struct CustomAllocBackend<Key: KeyId, Alloc: Allocator + Send + Sync> {
    map: hashbrown::HashMap<Key, Key::KeyValue, hashbrown::DefaultHashBuilder, Alloc>,
}

impl<Key: KeyId, Alloc: Allocator + Send + Sync> CustomAllocBackend<Key, Alloc> {
    pub(super) fn new(alloc: Alloc) -> Self {
        Self {
            map: hashbrown::HashMap::new_in(alloc),
        }
    }
}

impl<Key: KeyId, Alloc: Allocator + Send + Sync> ZeroizeOnDrop for CustomAllocBackend<Key, Alloc> {}

impl<Key: KeyId, Alloc: Allocator + Send + Sync> StoreBackend<Key>
    for CustomAllocBackend<Key, Alloc>
{
    fn upsert(&mut self, key_id: Key, key: <Key as KeyId>::KeyValue) {
        self.map.insert(key_id, key);
    }

    fn get(&self, key_id: Key) -> Option<&<Key as KeyId>::KeyValue> {
        self.map.get(&key_id)
    }

    fn remove(&mut self, key_id: Key) {
        self.map.remove(&key_id);
    }

    fn clear(&mut self) {
        self.map.clear();
    }

    fn retain(&mut self, f: fn(Key) -> bool) {
        self.map.retain(|key, _| f(*key));
    }
}

#[cfg(test)]
impl<Key: KeyId, Alloc: Allocator + Send + Sync> super::super::StoreBackendDebug<Key>
    for CustomAllocBackend<Key, Alloc>
{
    fn elements(&self) -> Vec<(Key, &Key::KeyValue)> {
        self.map.iter().map(|(k, v)| (*k, v)).collect()
    }
}

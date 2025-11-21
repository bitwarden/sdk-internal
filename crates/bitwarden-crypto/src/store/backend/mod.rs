use zeroize::ZeroizeOnDrop;

use crate::store::KeyId;

mod implementation;

pub use implementation::create_store;

/// This trait represents a platform that can store and return keys. If possible,
/// it will try to enable as many security protections on the keys as it can.
/// The keys themselves implement [ZeroizeOnDrop], so the store will only need to make sure
/// that the keys are dropped when they are no longer needed.
///
/// The default implementation is a basic in-memory store that does not provide any security
/// guarantees.
///
/// We have other implementations in testing using `mlock` and `memfd_secret` for protecting keys in
/// memory.
///
/// Other implementations could use secure enclaves, HSMs or OS provided keychains.
pub trait StoreBackend<Key: KeyId>: ZeroizeOnDrop + Send + Sync {
    /// Inserts a key into the store. If the key already exists, it will be replaced.
    fn upsert(&mut self, key_id: Key, key: Key::KeyValue);

    /// Retrieves a key from the store.
    fn get(&self, key_id: Key) -> Option<&Key::KeyValue>;

    #[expect(unused)]
    /// Removes a key from the store.
    fn remove(&mut self, key_id: Key);

    /// Removes all keys from the store.
    fn clear(&mut self);

    /// Retains only the elements specified by the predicate.
    /// In other words, remove all keys for which `f` returns false.
    fn retain(&mut self, f: fn(Key) -> bool);
}

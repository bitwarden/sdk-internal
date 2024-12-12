use zeroize::ZeroizeOnDrop;

use crate::store::KeyRef;

mod implementation;
mod slice_backend;

pub use implementation::create_store;

/// This trait represents a platform that can securely store and return keys. The `SliceBackend`
/// implementation is a simple store backed by a fixed size slice. Otherimplementations
/// could use secure enclaves or HSMs, or OS provided keychains.
pub trait StoreBackend<Key: KeyRef>: ZeroizeOnDrop + Send + Sync {
    fn insert(&mut self, key_ref: Key, key: Key::KeyValue);
    fn get(&self, key_ref: Key) -> Option<&Key::KeyValue>;
    fn remove(&mut self, key_ref: Key);
    fn clear(&mut self);

    fn retain(&mut self, f: fn(Key) -> bool);
}

use std::{
    any::{Any, TypeId},
    collections::HashMap,
    hash::Hash,
    sync::RwLock,
};

/// A concurrent map holding type-erased values. By default each value is keyed by its own type;
/// with an explicit key type, values are keyed by `K` and checked against the requested type on
/// read.
pub(crate) struct AnyMap<K = TypeId> {
    inner: RwLock<HashMap<K, Box<dyn Any + Send + Sync>>>,
}

impl<K: Eq + Hash> AnyMap<K> {
    /// Creates an empty map.
    pub(crate) fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Inserts a value under `key`, replacing any existing value, whatever its type.
    pub(crate) fn insert_at<V: Send + Sync + 'static>(&self, key: K, value: V) {
        self.inner
            .write()
            .expect("RwLock should not be poisoned")
            .insert(key, Box::new(value));
    }

    /// Retrieves a clone of the value under `key`: `None` if the key is absent, `Some(None)` if it
    /// holds a value of a type other than `V`.
    pub(crate) fn get_at<V: Clone + Send + Sync + 'static>(&self, key: &K) -> Option<Option<V>> {
        self.inner
            .read()
            .expect("RwLock should not be poisoned")
            .get(key)
            .map(|value| value.downcast_ref::<V>().cloned())
    }

    /// Removes all entries.
    pub(crate) fn clear(&self) {
        self.inner
            .write()
            .expect("RwLock should not be poisoned")
            .clear();
    }
}

impl AnyMap<TypeId> {
    /// Inserts a value under its own type, replacing any existing value of that type.
    ///
    /// The key is the static type of `value` at the call site, so any coercion has to happen
    /// before inserting: `Arc<ConcreteRepo>` and `Arc<dyn Repository<T>>` are different keys.
    pub(crate) fn insert<V: Send + Sync + 'static>(&self, value: V) {
        self.insert_at(TypeId::of::<V>(), value);
    }

    /// Retrieves a clone of the value of type `V`, or `None` if none was inserted.
    pub(crate) fn get<V: Clone + Send + Sync + 'static>(&self) -> Option<V> {
        self.get_at(&TypeId::of::<V>()).flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let map = AnyMap::<TypeId>::new();

        map.insert(42_u32);
        map.insert("hello".to_string());

        assert_eq!(map.get::<u32>(), Some(42));
        assert_eq!(map.get::<String>(), Some("hello".to_string()));
    }

    #[test]
    fn test_get_missing_type_returns_none() {
        let map = AnyMap::<TypeId>::new();
        map.insert(42_u32);

        assert_eq!(map.get::<String>(), None);
        assert_eq!(map.get::<u8>(), None);
    }

    #[test]
    fn test_insert_overwrites() {
        let map = AnyMap::<TypeId>::new();

        map.insert(1_u32);
        map.insert(2_u32);

        assert_eq!(map.get::<u32>(), Some(2));
    }

    #[test]
    fn test_clear() {
        let map = AnyMap::<TypeId>::new();
        map.insert(1_u32);
        map.insert("a".to_string());

        map.clear();

        assert_eq!(map.get::<u32>(), None);
        assert_eq!(map.get::<String>(), None);
    }

    #[test]
    fn test_keyed_get_distinguishes_absent_from_mismatched_type() {
        let map = AnyMap::<&'static str>::new();
        map.insert_at("a", 42_u32);

        assert_eq!(map.get_at::<u32>(&"a"), Some(Some(42)));
        assert_eq!(map.get_at::<String>(&"a"), Some(None));
        assert_eq!(map.get_at::<u32>(&"b"), None);
    }
}

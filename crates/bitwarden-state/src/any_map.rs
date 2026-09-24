use std::{
    any::{Any, TypeId},
    collections::HashMap,
    sync::RwLock,
};

/// A concurrent map holding type-erased values, each keyed by its own type.
pub(crate) struct AnyMap {
    inner: RwLock<HashMap<TypeId, Box<dyn Any + Send + Sync>>>,
}

impl AnyMap {
    /// Creates an empty map.
    pub(crate) fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Inserts a value under its own type, replacing any existing value of that type.
    ///
    /// The key is the static type of `value` at the call site, so any coercion has to happen
    /// before inserting: `Arc<ConcreteRepo>` and `Arc<dyn Repository<T>>` are different keys.
    pub(crate) fn insert<V: Send + Sync + 'static>(&self, value: V) {
        self.inner
            .write()
            .expect("RwLock should not be poisoned")
            .insert(TypeId::of::<V>(), Box::new(value));
    }

    /// Retrieves a clone of the value of type `V`, or `None` if none was inserted.
    pub(crate) fn get<V: Clone + Send + Sync + 'static>(&self) -> Option<V> {
        self.inner
            .read()
            .expect("RwLock should not be poisoned")
            .get(&TypeId::of::<V>())
            .and_then(|value| value.downcast_ref::<V>())
            .cloned()
    }

    /// Removes all entries.
    pub(crate) fn clear(&self) {
        self.inner
            .write()
            .expect("RwLock should not be poisoned")
            .clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let map = AnyMap::new();

        map.insert(42_u32);
        map.insert("hello".to_string());

        assert_eq!(map.get::<u32>(), Some(42));
        assert_eq!(map.get::<String>(), Some("hello".to_string()));
    }

    #[test]
    fn test_get_missing_type_returns_none() {
        let map = AnyMap::new();
        map.insert(42_u32);

        assert_eq!(map.get::<String>(), None);
        assert_eq!(map.get::<u8>(), None);
    }

    #[test]
    fn test_insert_overwrites() {
        let map = AnyMap::new();

        map.insert(1_u32);
        map.insert(2_u32);

        assert_eq!(map.get::<u32>(), Some(2));
    }

    #[test]
    fn test_clear() {
        let map = AnyMap::new();
        map.insert(1_u32);
        map.insert("a".to_string());

        map.clear();

        assert_eq!(map.get::<u32>(), None);
        assert_eq!(map.get::<String>(), None);
    }
}

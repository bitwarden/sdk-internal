use super::StoreBackend;
use crate::store::KeyRef;

mod basic;

/// Initializes a key store backend with the best available implementation for the current platform
pub fn create_store<Key: KeyRef>() -> Box<dyn StoreBackend<Key>> {
    Box::new(basic::BasicBackend::<Key>::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{key_ref::tests::TestSymmKey, SymmetricCryptoKey};

    #[test]
    fn test_creates_a_valid_store() {
        let mut store = create_store::<TestSymmKey>();

        let key = SymmetricCryptoKey::generate(rand::thread_rng());
        store.upsert(TestSymmKey::A(0), key.clone());

        assert_eq!(
            store.get(TestSymmKey::A(0)).unwrap().to_base64(),
            key.to_base64()
        );
    }
}

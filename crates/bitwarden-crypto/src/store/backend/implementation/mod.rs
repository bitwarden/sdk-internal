use super::StoreBackend;
use crate::store::KeyId;

mod custom_slice;

/// Initializes a key store backend with the best available implementation for the current platform
pub fn create_store<Key: KeyId>() -> Box<dyn StoreBackend<Key>> {
    #[cfg(all(target_os = "linux", not(feature = "no-memory-hardening")))]
    if let Some(key_store) = custom_slice::linux_memfd_secret::LinuxMemfdSecretBackend::<Key>::new()
    {
        return Box::new(key_store);
    }

    Box::new(
        custom_slice::rust::RustBackend::new().expect("RustKeyStore should always be available"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{traits::tests::TestSymmKey, SymmetricCryptoKey};

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

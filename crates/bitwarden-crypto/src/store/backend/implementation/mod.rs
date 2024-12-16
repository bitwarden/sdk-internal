use super::{slice_backend, StoreBackend};
use crate::store::KeyRef;

#[cfg(all(target_os = "linux", not(feature = "no-memory-hardening")))]
pub(crate) mod linux_memfd_secret;
pub(crate) mod rust;

/// Initializes a key store backend with the best available implementation for the current platform
pub fn create_store<Key: KeyRef>() -> Box<dyn StoreBackend<Key>> {
    #[cfg(all(target_os = "linux", not(feature = "no-memory-hardening")))]
    if let Some(key_store) = linux_memfd_secret::LinuxMemfdSecretBackend::<Key>::new() {
        return Box::new(key_store);
    }

    Box::new(rust::RustBackend::new().expect("RustKeyStore should always be available"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{key_ref::tests::TestSymmKey, SymmetricCryptoKey};

    #[test]
    fn test_creates_a_valid_store() {
        let mut store = create_store::<TestSymmKey>();

        let key = SymmetricCryptoKey::generate(rand::thread_rng());
        store.insert(TestSymmKey::A(0), key.clone());

        assert_eq!(
            store.get(TestSymmKey::A(0)).unwrap().to_base64(),
            key.to_base64()
        );
    }
}
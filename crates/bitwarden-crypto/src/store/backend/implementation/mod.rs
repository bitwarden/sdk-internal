use super::StoreBackend;
use crate::store::KeyId;

mod basic;

/// Initializes a key store backend with the best available implementation for the current platform
pub fn create_store<Key: KeyId>() -> Box<dyn StoreBackend<Key>> {
    Box::new(basic::BasicBackend::<Key>::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SymmetricCryptoKey, traits::tests::TestSymmKey};

    #[test]
    fn test_creates_a_valid_store() {
        let mut store = create_store::<TestSymmKey>();

        let key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        store.upsert(TestSymmKey::A(0), key.clone());

        assert_eq!(
            store.get(TestSymmKey::A(0)).unwrap().to_base64(),
            key.to_base64()
        );
    }
}

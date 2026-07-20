use crate::{KeySlotIds, KeyStoreContext, SymmetricKeyAlgorithm};

/// A key-encryption-key (KEK): a key that can be used to encrypt other keys, and shared between
/// users. It MAY be re-used for multiple encrypt operations.
///
/// See the `key_hierarchy` module documentation for its place in the key hierarchy.
pub struct KeyEncryptionKey;

impl KeyEncryptionKey {
    /// Generates a fresh key-encryption-key, stores it in the key store context, and returns its
    /// key id. Key material never leaves the key store.
    pub fn make<Ids: KeySlotIds>(ctx: &mut KeyStoreContext<Ids>) -> Ids::Symmetric {
        // XAES-256-GCM is used because a KEK is reused: the same key wraps many other keys over its
        // lifetime, and each wrap draws a fresh random nonce under that one key. Plain AES-256-GCM
        // has only a 96-bit nonce, so across the many encryptions a long-lived KEK performs, two
        // random nonces could eventually collide -- and a nonce reuse in GCM is catastrophic (it
        // leaks the authentication subkey and the XOR of the affected plaintexts). XAES-256-GCM
        // extends the nonce to 192 bits, making random-nonce collisions negligible even under heavy
        // reuse.
        ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm)
    }

    /// Returns whether the symmetric key `key_id` refers to uses an algorithm permitted for a
    /// key-encryption-key. Returns `false` if the key is missing or uses an unsupported algorithm.
    pub(crate) fn is_key_algorithm_valid<Ids: KeySlotIds>(
        ctx: &KeyStoreContext<Ids>,
        key_id: Ids::Symmetric,
    ) -> bool {
        let Ok(algorithm) = ctx.get_symmetric_key_algorithm(key_id) else {
            return false;
        };
        matches!(algorithm, SymmetricKeyAlgorithm::XAes256Gcm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KeyStore, SymmetricCryptoKey, traits::tests::TestIds};

    #[test]
    fn make_generates_xaes256_gcm_key_in_context() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let kek_id = KeyEncryptionKey::make(&mut ctx);

        let key = ctx.get_symmetric_key(kek_id).expect("KEK should be stored");
        assert!(matches!(key, SymmetricCryptoKey::XAes256GcmKey(_)));
    }

    #[test]
    fn make_generates_distinct_keys() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let first = KeyEncryptionKey::make(&mut ctx);
        let second = KeyEncryptionKey::make(&mut ctx);

        ctx.assert_symmetric_keys_not_equal(first, second);
    }

    #[test]
    fn is_key_algorithm_valid_accepts_kek_algorithms() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        for algorithm in [SymmetricKeyAlgorithm::XAes256Gcm] {
            let key_id = ctx.make_symmetric_key(algorithm);
            assert!(KeyEncryptionKey::is_key_algorithm_valid(&ctx, key_id));
        }
    }

    #[test]
    fn is_key_algorithm_valid_rejects_non_kek_algorithms() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        for algorithm in [
            SymmetricKeyAlgorithm::Aes256Gcm,
            SymmetricKeyAlgorithm::XChaCha20Poly1305,
            SymmetricKeyAlgorithm::Aes256CbcHmac,
        ] {
            let key_id = ctx.make_symmetric_key(algorithm);
            assert!(!KeyEncryptionKey::is_key_algorithm_valid(&ctx, key_id));
        }
    }
}

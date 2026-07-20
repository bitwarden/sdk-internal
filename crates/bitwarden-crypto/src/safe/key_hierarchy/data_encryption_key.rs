use crate::{KeySlotIds, KeyStoreContext, SymmetricKeyAlgorithm};

/// A data-encryption-key (DEK) - alternatively content-encryption-key (CEK) - a single-use
/// symmetric key that encrypts content directly. It SHALL NOT be re-used for multiple encrypt
/// operations.
///
/// See the `key_hierarchy` module documentation for its place in the key hierarchy.
pub struct DataEncryptionKey;

impl DataEncryptionKey {
    /// Generates a fresh data-encryption-key, stores it in the key store context, and returns its
    /// key id.
    pub fn make<Ids: KeySlotIds>(ctx: &mut KeyStoreContext<Ids>) -> Ids::Symmetric {
        // AES-256-GCM is used because a DEK is never reused: a new one is generated for each piece
        // of content, and it only ever performs a single encryption before being used solely to
        // decrypt that content. Because the key is unique per encryption, the 96-bit AES-256-GCM
        // nonce never risks a collision under it, so the extended-nonce variant a reused key
        // requires is unnecessary here.
        ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256Gcm)
    }

    /// Returns whether the symmetric key `key_id` refers to uses an algorithm permitted for a
    /// data-encryption-key. Returns `false` if the key is missing or uses an unsupported algorithm.
    #[allow(unused)]
    pub(crate) fn is_key_algorithm_valid<Ids: KeySlotIds>(
        ctx: &KeyStoreContext<Ids>,
        key_id: Ids::Symmetric,
    ) -> bool {
        let Ok(algorithm) = ctx.get_symmetric_key_algorithm(key_id) else {
            return false;
        };
        matches!(algorithm, SymmetricKeyAlgorithm::Aes256Gcm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KeyStore, SymmetricCryptoKey, traits::tests::TestIds};

    #[test]
    fn make_generates_aes256_gcm_key_in_context() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let dek_id = DataEncryptionKey::make(&mut ctx);

        let key = ctx.get_symmetric_key(dek_id).expect("DEK should be stored");
        assert!(matches!(key, SymmetricCryptoKey::Aes256GcmKey(_)));
    }

    #[test]
    fn make_generates_distinct_keys() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let first = DataEncryptionKey::make(&mut ctx);
        let second = DataEncryptionKey::make(&mut ctx);

        ctx.assert_symmetric_keys_not_equal(first, second);
    }

    #[test]
    fn is_key_algorithm_valid_accepts_dek_algorithms() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        for algorithm in [SymmetricKeyAlgorithm::Aes256Gcm] {
            let key_id = ctx.make_symmetric_key(algorithm);
            assert!(DataEncryptionKey::is_key_algorithm_valid(&ctx, key_id));
        }
    }

    #[test]
    fn is_key_algorithm_valid_rejects_non_dek_algorithms() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        for algorithm in [
            SymmetricKeyAlgorithm::XChaCha20Poly1305,
            SymmetricKeyAlgorithm::XAes256Gcm,
            SymmetricKeyAlgorithm::Aes256CbcHmac,
        ] {
            let key_id = ctx.make_symmetric_key(algorithm);
            assert!(!DataEncryptionKey::is_key_algorithm_valid(&ctx, key_id));
        }
    }
}

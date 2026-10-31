use crate::{CoseKeyView, KeySlotIds, KeyStoreContext, SymmetricCryptoKey, SymmetricKeyAlgorithm};

/// A key-encryption-key (KEK): a key that can be used to encrypt other keys, and shared between
/// users. It MAY be re-used for multiple encrypt operations.
///
/// New KEKs are XAES-256-GCM keys (see [`KeyEncryptionKey::make`]). AES-256-CBC-HMAC keys are also
/// accepted as KEKs, so that existing (V1) keys that act as KEKs, such as user keys and cipher
/// keys, can adopt safe objects before they are rotated. AES-256-CBC-HMAC uses a random 128-bit IV,
/// so it does not have the nonce-reuse problem that rules out plain AES-256-GCM for a reused key.
///
/// See the `key_hierarchy` module documentation for its place in the key hierarchy.
pub struct KeyEncryptionKey;

/// The reasons a key cannot be used as a [`KeyEncryptionKey`].
#[derive(Debug)]
pub(crate) enum KeyEncryptionKeyError {
    /// There is no key in the given key slot.
    Missing,
    /// The key uses an algorithm that is not permitted for a key-encryption-key.
    WrongKeyType,
}

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

    /// Looks up the symmetric key `key_id` refers to and returns a [`CoseKeyView`] of it, if it is
    /// an XAES-256-GCM or AES-256-CBC-HMAC key, the algorithms accepted for a [`KeyEncryptionKey`].
    pub(crate) fn get_cose_key_view<'k, Ids: KeySlotIds>(
        ctx: &'k KeyStoreContext<'_, Ids>,
        key_id: Ids::Symmetric,
    ) -> Result<CoseKeyView<'k>, KeyEncryptionKeyError> {
        match ctx
            .get_symmetric_key(key_id)
            .map_err(|_| KeyEncryptionKeyError::Missing)?
        {
            SymmetricCryptoKey::XAes256GcmKey(key) => Ok(CoseKeyView::XAes256Gcm(key)),
            SymmetricCryptoKey::Aes256CbcHmacKey(key) => Ok(CoseKeyView::Aes256CbcHmac(key)),
            _ => Err(KeyEncryptionKeyError::WrongKeyType),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        KeyStore,
        cose::symmetric::CoseContentEncryptionAlgorithm,
        traits::tests::{TestIds, TestSymmKey},
    };

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
    fn get_cose_key_view_accepts_kek_algorithms() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        for (algorithm, expected_cose_algorithm) in [
            (
                SymmetricKeyAlgorithm::XAes256Gcm,
                CoseContentEncryptionAlgorithm::XAes256Gcm,
            ),
            (
                SymmetricKeyAlgorithm::Aes256CbcHmac,
                CoseContentEncryptionAlgorithm::Aes256CbcHmacSha256,
            ),
        ] {
            let key_id = ctx.make_symmetric_key(algorithm);
            let view = KeyEncryptionKey::get_cose_key_view(&ctx, key_id)
                .expect("KEK algorithm should be accepted");
            assert_eq!(view.algorithm(), expected_cose_algorithm);
        }
    }

    #[test]
    fn get_cose_key_view_rejects_non_kek_algorithms() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        for algorithm in [
            SymmetricKeyAlgorithm::Aes256Gcm,
            SymmetricKeyAlgorithm::XChaCha20Poly1305,
        ] {
            let key_id = ctx.make_symmetric_key(algorithm);
            assert!(matches!(
                KeyEncryptionKey::get_cose_key_view(&ctx, key_id),
                Err(KeyEncryptionKeyError::WrongKeyType)
            ));
        }
    }

    #[test]
    fn get_cose_key_view_rejects_missing_key() {
        let key_store = KeyStore::<TestIds>::default();
        let ctx = key_store.context();

        assert!(matches!(
            KeyEncryptionKey::get_cose_key_view(&ctx, TestSymmKey::A(0)),
            Err(KeyEncryptionKeyError::Missing)
        ));
    }
}

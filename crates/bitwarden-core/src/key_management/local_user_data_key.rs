use bitwarden_crypto::{EncString, KeyStoreContext};
use key_management::LocalUserDataKeyState;
use thiserror::Error;
use tracing::instrument;

use crate::{
    key_management,
    key_management::{KeyIds, SymmetricKeyId},
};

/// An indirect symmetric key for encrypting local user data (e.g. password generator history).
/// Enables offline decryption of local data after a key rotation: only the wrapped key is
/// re-encrypted; the local user data key itself stays intact.
#[derive(Debug, Clone)]
pub(crate) struct WrappedLocalUserDataKey(EncString);

impl WrappedLocalUserDataKey {
    /// Create a user key, wrapped by the user key.
    #[instrument(skip(ctx), err)]
    pub(crate) fn from_user_key(
        ctx: &mut KeyStoreContext<KeyIds>,
    ) -> Result<Self, LocalUserDataKeyError> {
        let wrapped_local_user_data_key = ctx
            .wrap_symmetric_key(SymmetricKeyId::User, SymmetricKeyId::User)
            .map_err(|_| LocalUserDataKeyError::EncryptionFailed)?;
        Ok(WrappedLocalUserDataKey(wrapped_local_user_data_key))
    }

    /// Decrypt the wrapped key and sets it to context.
    ///
    /// # Arguments
    ///
    /// * `wrapping_key` - The key id of the key used to unwrap the local user data key. It must
    ///   already exist in the context.
    #[allow(unused)]
    #[instrument(skip(self, ctx), err)]
    pub(crate) fn set_to_context(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
    ) -> Result<SymmetricKeyId, LocalUserDataKeyError> {
        ctx.unwrap_symmetric_key(SymmetricKeyId::User, &self.0)
            .map_err(|_| LocalUserDataKeyError::DecryptionFailed)
    }
}

/// Errors that can occur when working with [`WrappedLocalUserDataKey`].
#[derive(Debug, Error)]
pub enum LocalUserDataKeyError {
    /// Decryption of a wrapped key failed
    #[error("Decryption failed")]
    DecryptionFailed,
    /// Failed to encrypt a key
    #[error("Encryption failed")]
    EncryptionFailed,
}

impl From<WrappedLocalUserDataKey> for LocalUserDataKeyState {
    fn from(wrapped_key: WrappedLocalUserDataKey) -> Self {
        Self {
            wrapped_key: wrapped_key.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{Decryptable, KeyStore, PrimitiveEncryptable};

    use super::*;
    use crate::key_management::{KeyIds, SymmetricKeyId};

    fn make_key_store_with_user_key() -> KeyStore<KeyIds> {
        let key_store = KeyStore::<KeyIds>::default();
        let mut ctx = key_store.context_mut();
        let user_key = ctx.generate_symmetric_key();
        ctx.persist_symmetric_key(user_key, SymmetricKeyId::User)
            .expect("persisting user key should succeed");
        drop(ctx);
        key_store
    }

    #[test]
    fn test_round_trip() {
        let key_store = make_key_store_with_user_key();
        let mut ctx = key_store.context_mut();

        let plaintext = "test local user data";
        let ciphertext = plaintext
            .encrypt(&mut ctx, SymmetricKeyId::User)
            .expect("encryption should succeed");

        let wrapped =
            WrappedLocalUserDataKey::from_user_key(&mut ctx).expect("wrapping should succeed");

        let unwrapped_key = wrapped
            .set_to_context(&mut ctx)
            .expect("unwrapping should succeed");

        let decrypted: String = ciphertext
            .decrypt(&mut ctx, unwrapped_key)
            .expect("decryption with unwrapped key should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_set_to_context_fails_with_wrong_key() {
        let key_store_a = make_key_store_with_user_key();
        let wrapped = {
            let mut ctx = key_store_a.context_mut();
            WrappedLocalUserDataKey::from_user_key(&mut ctx).expect("wrapping should succeed")
        };

        let key_store_b = make_key_store_with_user_key();
        let mut ctx_b = key_store_b.context_mut();
        assert!(
            wrapped.set_to_context(&mut ctx_b).is_err(),
            "unwrapping with a different key should fail"
        );
    }
}

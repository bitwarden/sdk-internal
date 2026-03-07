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
pub(crate) struct WrappedLocalUserDataKey(pub(crate) EncString);

impl WrappedLocalUserDataKey {
    /// Create a user key, wrapped by the user key.
    #[instrument(skip(ctx), err)]
    pub(crate) fn from_context_user_key(
        ctx: &mut KeyStoreContext<KeyIds>,
    ) -> Result<Self, LocalUserDataKeyError> {
        let wrapped_local_user_data_key = ctx
            .wrap_symmetric_key(SymmetricKeyId::User, SymmetricKeyId::User)
            .map_err(|_| LocalUserDataKeyError::EncryptionFailed)?;
        Ok(WrappedLocalUserDataKey(wrapped_local_user_data_key))
    }

    /// Unwrap the local user data key and set it in the context under the
    /// [`SymmetricKeyId::LocalUserData`] key id.
    #[instrument(skip(self, ctx), err)]
    pub(crate) fn unwrap_to_context(
        &self,
        ctx: &mut KeyStoreContext<KeyIds>,
    ) -> Result<(), LocalUserDataKeyError> {
        let local_id = ctx
            .unwrap_symmetric_key(SymmetricKeyId::User, &self.0)
            .map_err(|_| LocalUserDataKeyError::DecryptionFailed)?;
        ctx.persist_symmetric_key(local_id, SymmetricKeyId::LocalUserData)
            .map_err(|_| LocalUserDataKeyError::DecryptionFailed)?;
        Ok(())
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
    fn test_from_context_user_key_wraps_user_key() {
        let key_store = make_key_store_with_user_key();
        let mut ctx = key_store.context_mut();

        let plaintext = "test data";
        let ciphertext = plaintext
            .encrypt(&mut ctx, SymmetricKeyId::User)
            .expect("encryption with user key should succeed");

        let wrapped = WrappedLocalUserDataKey::from_context_user_key(&mut ctx)
            .expect("wrapping should succeed");
        wrapped
            .unwrap_to_context(&mut ctx)
            .expect("unwrapping should succeed");

        // Verify LocalUserData key is the same as User key: data encrypted with User
        // must be decryptable with LocalUserData.
        let decrypted: String = ciphertext
            .decrypt(&mut ctx, SymmetricKeyId::LocalUserData)
            .expect("decryption with local user data key should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_unwrap_to_context_fails_with_wrong_key() {
        let key_store_a = make_key_store_with_user_key();
        let wrapped = {
            let mut ctx = key_store_a.context_mut();
            WrappedLocalUserDataKey::from_context_user_key(&mut ctx)
                .expect("wrapping should succeed")
        };

        let key_store_b = make_key_store_with_user_key();
        let mut ctx_b = key_store_b.context_mut();
        assert!(
            wrapped.unwrap_to_context(&mut ctx_b).is_err(),
            "unwrapping with a different key should fail"
        );
    }
}

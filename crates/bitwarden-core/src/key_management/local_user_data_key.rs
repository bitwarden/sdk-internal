use bitwarden_crypto::{EncString, KeyStoreContext};
use key_management::LocalUserDataKeyState;
use thiserror::Error;

use crate::{
    key_management,
    key_management::{KeySlotIds, SymmetricKeySlotId},
};

/// An indirect symmetric key for encrypting local user data (e.g. password generator history).
/// Enables offline decryption of local data after a key rotation: only the wrapped key is
/// re-encrypted; the local user data key itself stays intact.
#[derive(Debug, Clone)]
pub(crate) struct WrappedLocalUserDataKey(pub(crate) EncString);

impl WrappedLocalUserDataKey {
    /// Create a user key, wrapped by the user key.
    #[bitwarden_logging::instrument(err)]
    pub(crate) fn from_context_user_key(
        ctx: &mut KeyStoreContext<KeySlotIds>,
    ) -> Result<Self, LocalUserDataKeyError> {
        let wrapped_local_user_data_key = ctx
            .wrap_symmetric_key(SymmetricKeySlotId::User, SymmetricKeySlotId::User)
            .map_err(|_| LocalUserDataKeyError::EncryptionFailed)?;
        Ok(WrappedLocalUserDataKey(wrapped_local_user_data_key))
    }

    /// Re-wrap an existing wrapped local user data key, preserving the inner key plaintext but
    /// changing the wrapping key from `old_wrapping_key_id` to the current
    /// [`SymmetricKeySlotId::User`].
    ///
    /// Used during V1→V2 user-key upgrades: the wrapped key was previously sealed with the V1
    /// user key and must be re-sealed with the V2 user key so that local data encrypted under
    /// the local user data key remains decryptable after rotation.
    #[bitwarden_logging::instrument(err, fields(old_wrapping_key_id = ?old_wrapping_key_id))]
    pub(crate) fn rewrap_with_user_key(
        &self,
        old_wrapping_key_id: SymmetricKeySlotId,
        ctx: &mut KeyStoreContext<KeySlotIds>,
    ) -> Result<Self, LocalUserDataKeyError> {
        let local_id = ctx
            .unwrap_symmetric_key(old_wrapping_key_id, &self.0)
            .map_err(|_| LocalUserDataKeyError::DecryptionFailed)?;
        let new_wrapped = ctx
            .wrap_symmetric_key(SymmetricKeySlotId::User, local_id)
            .map_err(|_| LocalUserDataKeyError::EncryptionFailed)?;
        Ok(WrappedLocalUserDataKey(new_wrapped))
    }

    /// Unwrap the local user data key and set it in the context under the
    /// [`SymmetricKeySlotId::LocalUserData`] key id.
    #[bitwarden_logging::instrument(err)]
    pub(crate) fn unwrap_to_context(
        &self,
        ctx: &mut KeyStoreContext<KeySlotIds>,
    ) -> Result<(), LocalUserDataKeyError> {
        let local_id = ctx
            .unwrap_symmetric_key(SymmetricKeySlotId::User, &self.0)
            .map_err(|_| LocalUserDataKeyError::DecryptionFailed)?;
        ctx.persist_symmetric_key(local_id, SymmetricKeySlotId::LocalUserData)
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

impl From<&LocalUserDataKeyState> for WrappedLocalUserDataKey {
    fn from(state: &LocalUserDataKeyState) -> Self {
        Self(state.wrapped_key.clone())
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{Decryptable, KeyStore, PrimitiveEncryptable};

    use super::*;
    use crate::key_management::{KeySlotIds, SymmetricKeySlotId};

    fn make_key_store_with_user_key() -> KeyStore<KeySlotIds> {
        let key_store = KeyStore::<KeySlotIds>::default();
        let mut ctx = key_store.context_mut();
        let user_key = ctx.generate_symmetric_key();
        ctx.persist_symmetric_key(user_key, SymmetricKeySlotId::User)
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
            .encrypt(&mut ctx, SymmetricKeySlotId::User)
            .expect("encryption with user key should succeed");

        let wrapped = WrappedLocalUserDataKey::from_context_user_key(&mut ctx)
            .expect("wrapping should succeed");
        wrapped
            .unwrap_to_context(&mut ctx)
            .expect("unwrapping should succeed");

        // Verify LocalUserData key is the same as User key: data encrypted with User
        // must be decryptable with LocalUserData.
        let decrypted: String = ciphertext
            .decrypt(&mut ctx, SymmetricKeySlotId::LocalUserData)
            .expect("decryption with local user data key should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_rewrap_with_user_key_preserves_inner_plaintext() {
        use bitwarden_crypto::SymmetricKeyAlgorithm;

        let key_store = KeyStore::<KeySlotIds>::default();
        let mut ctx = key_store.context_mut();

        // Create an initial wrapped local user data key using a V1 user key.
        let v1_local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
        ctx.persist_symmetric_key(v1_local_key_id, SymmetricKeySlotId::User)
            .expect("persisting old user key should succeed");

        let wrapped_v1_local_key = WrappedLocalUserDataKey::from_context_user_key(&mut ctx)
            .expect("initial wrap should succeed");

        wrapped_v1_local_key
            .unwrap_to_context(&mut ctx)
            .expect("unwrap with old user key should succeed");
        let plaintext = "rewrap round-trip data";
        let ciphertext = plaintext
            .encrypt(&mut ctx, SymmetricKeySlotId::LocalUserData)
            .expect("encryption with LocalUserData slot should succeed");

        // Save v1 to a fresh local id before overwriting the User slot with v2.
        // Mirrors the production path where the V1→V2 upgrade token re-materializes
        // v1 into a local slot at rewrap time.
        let v1_old_wrapping_id = ctx
            .unwrap_symmetric_key(SymmetricKeySlotId::User, &wrapped_v1_local_key.0)
            .expect("unwrap with v1 user key should succeed");

        // Rewrap
        let new_local = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
        ctx.persist_symmetric_key(new_local, SymmetricKeySlotId::User)
            .expect("persisting new user key should succeed");
        let wrapped_new = wrapped_v1_local_key
            .rewrap_with_user_key(v1_old_wrapping_id, &mut ctx)
            .expect("rewrap should succeed");

        // Validate that the new wrapped version can still decrypt the data
        wrapped_new
            .unwrap_to_context(&mut ctx)
            .expect("unwrap with new user key should succeed");

        let decrypted: String = ciphertext
            .decrypt(&mut ctx, SymmetricKeySlotId::LocalUserData)
            .expect("decryption after rewrap should succeed");
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

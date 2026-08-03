//! Report the key id of the current user key to the server.
//!
//! Accounts created before the key id was submitted alongside key material have no key id stored
//! server-side. This submits it via `POST /accounts/key-management/user-key-id`, which the server
//! only accepts while the account has no key id — the value otherwise changes only through a key
//! rotation.

use bitwarden_api_api::models::SetUserKeyIdRequestModel;
use bitwarden_core::key_management::{KeySlotIds, SymmetricKeySlotId};
use bitwarden_crypto::{KeyId, KeyStore};
use bitwarden_error::bitwarden_error;
use thiserror::Error;
use tracing::{error, info};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::UserCryptoManagementClient;

/// Errors that can occur while reporting the user key id to the server.
#[derive(Debug, Error)]
#[bitwarden_error(flat)]
pub enum PostUserKeyIdError {
    /// The client is locked, or otherwise has no user key in its key store.
    #[error("User key is not available in key store")]
    UserKeyNotAvailable,
    /// The user key does not carry a key id.
    #[error("User key has no key id")]
    NoKeyId,
    /// The server rejected the request, most likely because it already has a key id.
    #[error("API call failed while posting the user key id")]
    Api,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[cfg_attr(feature = "uniffi", uniffi::export(async_runtime = "tokio"))]
impl UserCryptoManagementClient {
    /// Reports the key id of the current user key to the server.
    ///
    /// The key id is read from the key store rather than taken as an argument, so a caller cannot
    /// report an id that does not match the key actually in use. Requires the client to be
    /// unlocked, and that the user key carries a key id.
    ///
    /// Fails with [`PostUserKeyIdError::Api`] when the server already has a key id for the
    /// account.
    pub async fn post_user_key_id(&self) -> Result<(), PostUserKeyIdError> {
        // NOTE: the KeyStoreContext is dropped inside the helper, before the await below.
        let user_key_id = current_user_key_id(self.client.internal.get_key_store())?;

        info!("Posting user key id to server");
        self.client
            .internal
            .get_api_configurations()
            .api_client
            .accounts_key_management_api()
            .post_user_key_id(Some(SetUserKeyIdRequestModel {
                user_key_id: user_key_id.to_hex(),
            }))
            .await
            .map_err(|e| {
                error!("Failed to post user key id to server: {e:?}");
                PostUserKeyIdError::Api
            })?;

        Ok(())
    }
}

/// Reads the key id of the current user key out of the key store.
fn current_user_key_id(key_store: &KeyStore<KeySlotIds>) -> Result<KeyId, PostUserKeyIdError> {
    let ctx = key_store.context();
    if !ctx.has_symmetric_key(SymmetricKeySlotId::User) {
        return Err(PostUserKeyIdError::UserKeyNotAvailable);
    }
    ctx.get_symmetric_key_id(SymmetricKeySlotId::User)
        .ok_or(PostUserKeyIdError::NoKeyId)
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::SymmetricKeyAlgorithm;

    use super::*;

    fn key_store_with_user_key(algorithm: SymmetricKeyAlgorithm) -> KeyStore<KeySlotIds> {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        {
            let mut ctx = store.context_mut();
            let local = ctx.make_symmetric_key(algorithm);
            ctx.persist_symmetric_key(local, SymmetricKeySlotId::User)
                .expect("setting the user key should succeed");
        }
        store
    }

    #[test]
    fn returns_the_key_id_when_the_user_key_carries_one() {
        let store = key_store_with_user_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let expected = store
            .context()
            .get_symmetric_key_id(SymmetricKeySlotId::User)
            .expect("this key algorithm carries a key id");

        let user_key_id = current_user_key_id(&store).expect("should read the key id");

        assert_eq!(user_key_id, expected);
        // The value posted to the server is the lowercase hex form.
        assert_eq!(user_key_id.to_hex().len(), 32);
    }

    #[test]
    fn returns_no_key_id_when_the_user_key_carries_none() {
        let store = key_store_with_user_key(SymmetricKeyAlgorithm::Aes256CbcHmac);

        let result = current_user_key_id(&store);

        assert!(matches!(result, Err(PostUserKeyIdError::NoKeyId)));
    }

    #[test]
    fn returns_user_key_not_available_when_locked() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();

        let result = current_user_key_id(&store);

        assert!(matches!(
            result,
            Err(PostUserKeyIdError::UserKeyNotAvailable)
        ));
    }
}

use bitwarden_crypto::LocalUserDataKey;
use bitwarden_encoding::B64;
use tracing::info;

use crate::{
    Client,
    key_management::{self, SymmetricKeyId},
};

// Single-entry repository; empty string is the key.
const LOCAL_USER_DATA_KEY_REPOSITORY_KEY: &str = "";

pub(crate) struct InitLocalUserDataKeyError;

/// Stores an encrypted `LocalUserDataKey` in client-managed state if one does not already exist.
pub(crate) async fn initialize_local_user_data_key(
    client: &Client,
) -> Result<(), InitLocalUserDataKeyError> {
    let user_key = {
        let key_store = client.internal.get_key_store();
        let ctx = key_store.context();
        #[expect(deprecated)]
        ctx.dangerous_get_symmetric_key(SymmetricKeyId::User)
            .map_err(|_| InitLocalUserDataKeyError)?
            .clone()
    };

    let Ok(repo) = client
        .platform()
        .state()
        .get::<key_management::LocalUserDataKeyState>()
    else {
        info!("No LocalUserDataKeyState repository registered, exiting gracefully");
        return Ok(());
    };

    // Idempotent: only set if no key is present yet.
    if let Ok(Some(_)) = repo
        .get(LOCAL_USER_DATA_KEY_REPOSITORY_KEY.to_string())
        .await
    {
        info!("LocalUserDataKey already exists in client managed state, skipping");
        return Ok(());
    }

    info!("Setting LocalUserDataKey to client managed state from user key");
    let local_key = LocalUserDataKey::from_user_key(&user_key);
    let encrypted_key = local_key
        .encrypt_with_user_key(&user_key)
        .map_err(|_| InitLocalUserDataKeyError)?
        .to_buffer()
        .map_err(|_| InitLocalUserDataKeyError)
        .map(B64::from)?;

    repo.set(
        LOCAL_USER_DATA_KEY_REPOSITORY_KEY.to_string(),
        key_management::LocalUserDataKeyState { encrypted_key },
    )
    .await
    .map_err(|_| InitLocalUserDataKeyError)
}

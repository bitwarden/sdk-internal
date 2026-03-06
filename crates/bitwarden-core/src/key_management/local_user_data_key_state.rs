use tracing::info;

use crate::{
    Client,
    key_management::{self, local_user_data_key::WrappedLocalUserDataKey},
};

// Single-entry repository; empty string is the key.
const LOCAL_USER_DATA_KEY_REPOSITORY_KEY: &str = "";

pub(crate) struct InitLocalUserDataKeyError;

/// Stores [`WrappedLocalUserDataKey`] in state if one does not already exist.
pub(crate) async fn initialize_local_user_data_key(
    client: &Client,
) -> Result<(), InitLocalUserDataKeyError> {
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
        info!("WrappedLocalUserDataKey already exists in state, skipping");
        return Ok(());
    }

    info!("Setting LocalUserDataKey to state from user key");
    let wrapped_local_user_data_key = {
        let key_store = client.internal.get_key_store();
        let mut ctx = key_store.context();
        WrappedLocalUserDataKey::from_user_key(&mut ctx).map_err(|_| InitLocalUserDataKeyError)?
    };

    repo.set(
        LOCAL_USER_DATA_KEY_REPOSITORY_KEY.to_string(),
        wrapped_local_user_data_key.into(),
    )
    .await
    .map_err(|_| InitLocalUserDataKeyError)
}

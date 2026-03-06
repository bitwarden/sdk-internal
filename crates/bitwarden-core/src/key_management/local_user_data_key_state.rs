use tracing::info;

use crate::{
    Client,
    key_management::{self, local_user_data_key::WrappedLocalUserDataKey},
};

// Single-entry repository; empty string is the key.
const LOCAL_USER_DATA_KEY_REPOSITORY_KEY: &str = "";

pub(crate) struct InitLocalUserDataKeyError;

/// Stores [`WrappedLocalUserDataKey`] in state if one does not already exist.
pub(crate) async fn initialize_local_user_data_key_into_state(
    client: &Client,
) -> Result<(), InitLocalUserDataKeyError> {
    let repo = client
        .platform()
        .state()
        .get::<key_management::LocalUserDataKeyState>()
        .map_err(|_| InitLocalUserDataKeyError)?;

    // Idempotent: only set if no key is present yet.
    if let Ok(Some(_)) = repo
        .get(LOCAL_USER_DATA_KEY_REPOSITORY_KEY.to_string())
        .await
    {
        info!("WrappedLocalUserDataKey already exists in state, skipping");
        return Ok(());
    }

    info!("Setting WrappedLocalUserDataKey to state from user key");
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

pub(crate) struct UnableToGetError;

/// Retrieves the [`WrappedLocalUserDataKey`] from state.
pub(crate) async fn get_local_user_data_key_from_state(
    client: &Client,
) -> Result<WrappedLocalUserDataKey, UnableToGetError> {
    info!("Getting the WrappedLocalUserDataKey from state");
    let user_local_data_key_state = client
        .platform()
        .state()
        .get::<key_management::LocalUserDataKeyState>()
        .map_err(|_| UnableToGetError)?
        .get(LOCAL_USER_DATA_KEY_REPOSITORY_KEY.to_string())
        .await
        .map_err(|_| UnableToGetError)?
        .ok_or(UnableToGetError)?;

    Ok(WrappedLocalUserDataKey(
        user_local_data_key_state.wrapped_key,
    ))
}

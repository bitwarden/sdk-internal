use tracing::info;

use crate::{
    Client, UserId,
    key_management::{self, local_user_data_key::WrappedLocalUserDataKey},
};

pub(crate) struct InitLocalUserDataKeyError;

/// Stores [`WrappedLocalUserDataKey`] in state if one does not already exist.
pub(crate) async fn initialize_local_user_data_key_into_state(
    client: &Client,
    user_id: UserId,
) -> Result<(), InitLocalUserDataKeyError> {
    let repo = client
        .platform()
        .state()
        .get::<key_management::LocalUserDataKeyState>()
        .map_err(|_| InitLocalUserDataKeyError)?;

    // Idempotent: only set if no key is present yet.
    if let Ok(Some(_)) = repo.get(user_id).await {
        info!("WrappedLocalUserDataKey already exists in state, skipping");
        return Ok(());
    }

    info!("Setting WrappedLocalUserDataKey to state from user key");
    let wrapped_local_user_data_key = {
        let key_store = client.internal.get_key_store();
        let mut ctx = key_store.context();
        WrappedLocalUserDataKey::from_context_user_key(&mut ctx)
            .map_err(|_| InitLocalUserDataKeyError)?
    };

    repo.set(user_id, wrapped_local_user_data_key.into())
        .await
        .map_err(|_| InitLocalUserDataKeyError)
}

pub(crate) struct UnableToGetError;

/// Retrieves the [`WrappedLocalUserDataKey`] from state.
pub(crate) async fn get_local_user_data_key_from_state(
    client: &Client,
    user_id: UserId,
) -> Result<WrappedLocalUserDataKey, UnableToGetError> {
    info!("Getting the WrappedLocalUserDataKey from state");
    let user_local_data_key_state = client
        .platform()
        .state()
        .get::<key_management::LocalUserDataKeyState>()
        .map_err(|_| UnableToGetError)?
        .get(user_id)
        .await
        .map_err(|_| UnableToGetError)?
        .ok_or(UnableToGetError)?;

    Ok(WrappedLocalUserDataKey(
        user_local_data_key_state.wrapped_key,
    ))
}

pub(crate) struct UnableToRemoveError;
/// Removes the [`WrappedLocalUserDataKey`] from state.
pub(crate) async fn remove_local_user_data_key_from_state(
    client: &Client,
    user_id: UserId,
) -> Result<(), UnableToRemoveError> {
    info!("Removing the WrappedLocalUserDataKey from state");
    client
        .platform()
        .state()
        .get::<key_management::LocalUserDataKeyState>()
        .map_err(|_| UnableToRemoveError)?
        .remove(user_id)
        .await
        .map_err(|_| UnableToRemoveError)
}

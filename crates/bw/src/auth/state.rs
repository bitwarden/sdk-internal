//! Authentication state persistence for the CLI.
//!
//! This module handles persisting authentication state (user_id, tokens, login method)
//! to allow session restoration across CLI restarts.
//!
//! # Flow
//!
//! **Login:**
//! 1. User authenticates (password, API key, or device)
//! 2. [`save`] extracts tokens and login method from client
//! 3. Serializes [`PersistedAuthState`] to database
//!
//! **Startup:**
//! 1. [`load`] reads from database
//! 2. Deserializes to [`PersistedAuthState`]
//! 3. `main.rs` calls `restore_persisted_auth_state()` on client
//!
//! **Logout:**
//! 1. [`clear`] removes state from database
//! 2. Session will not be restored on next startup

use bitwarden_core::{Client, client::PersistedAuthState};
use bitwarden_state::register_setting_key;
use tracing::debug;

use crate::platform::StateError;

register_setting_key!(const AUTH: PersistedAuthState = "auth");

/// Save auth state to repository.
///
/// Extracts the current authentication state (user_id, tokens, login method) from the client
/// and serializes it to disk. This allows the CLI to restore sessions across restarts.
pub async fn save(client: &Client) -> Result<(), StateError> {
    let auth_state = client
        .internal
        .get_persisted_auth_state()
        .ok_or(StateError::NoAuthState)?;

    client
        .platform()
        .state()
        .setting(AUTH)?
        .update(auth_state)
        .await?;

    debug!("Auth state saved to disk");

    Ok(())
}

/// Load auth state from repository.
///
/// Reads the persisted authentication state from disk and deserializes it. This is called
/// on CLI startup to restore previous sessions.
pub async fn load(client: &Client) -> Result<Option<PersistedAuthState>, StateError> {
    match client.platform().state().setting(AUTH)?.get().await {
        Ok(auth_state) => {
            if auth_state.is_some() {
                debug!("Auth state loaded from disk");
            }
            Ok(auth_state)
        }
        Err(e) => {
            tracing::warn!("Failed to load auth state: {}", e);
            Err(e.into())
        }
    }
}

/// Clear auth state from repository.
///
/// Removes the persisted authentication state from disk. This is called during logout
/// to ensure the session is not restored on next startup.
pub async fn clear(client: &Client) -> Result<(), StateError> {
    client.platform().state().setting(AUTH)?.delete().await?;

    debug!("Auth state cleared from disk");
    Ok(())
}

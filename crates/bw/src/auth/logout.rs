use bitwarden_core::Client;
use color_eyre::eyre::{Result, eyre};
use tracing::info;

use crate::key_management::crypto::CryptoStateStore;

pub(crate) async fn logout(client: Client) -> Result<()> {
    // Check if logged in
    if client.internal.get_user_id().is_none() {
        return Err(eyre!("Not logged in"));
    }

    // Clear auth state from repository
    super::state::clear(&client).await?;

    // Clear crypto state (master password unlock data and wrapped account state)
    if let Ok(crypto_store) = CryptoStateStore::new(&client) {
        if let Err(e) = crypto_store.master_password_unlock.delete().await {
            tracing::warn!("Failed to clear master password unlock data: {}", e);
        }
        if let Err(e) = crypto_store.wrapped_state.delete().await {
            tracing::warn!("Failed to clear wrapped account crypto state: {}", e);
        }
    }

    // Clear encrypted user key
    if let Err(e) = crate::key_management::session::clear(&client).await {
        tracing::warn!("Failed to clear encrypted user key: {}", e);
    }

    info!("Logged out successfully");
    Ok(())
}

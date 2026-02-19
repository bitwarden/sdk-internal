//! Crypto state persistence for CLI sessions.
//!
//! This module handles persisting encrypted key material from sync responses
//! to allow vault unlock after CLI restart without re-authentication.
//!
//! # Persisted Keys
//!
//! - **Master Password Unlock Data**: KDF, salt, and encrypted user key for master password unlock
//! - **Wrapped Account Cryptographic State**: V1/V2 private keys and signing keys

use bitwarden_api_api::models::SyncResponseModel;
use bitwarden_core::{
    Client,
    key_management::{
        MasterPasswordUnlockData, account_cryptographic_state::WrappedAccountCryptographicState,
    },
};
use bitwarden_state::{Setting, register_setting_key};
use tracing::debug;

use crate::platform::StateError;

register_setting_key!(const MASTER_PASSWORD_UNLOCK: MasterPasswordUnlockData = "master_password_unlock");
register_setting_key!(const WRAPPED_ACCOUNT_CRYPTO_STATE: WrappedAccountCryptographicState = "wrapped_account_crypto_state");

/// Store for persisted crypto state.
///
/// Provides access to master password unlock data and wrapped account crypto state
/// settings needed for vault unlock after CLI restart.
pub struct CryptoStateStore {
    /// Master password unlock data (KDF, salt, encrypted user key)
    pub master_password_unlock: Setting<MasterPasswordUnlockData>,
    /// Wrapped account cryptographic state (private keys, signing keys)
    pub wrapped_state: Setting<WrappedAccountCryptographicState>,
}

impl CryptoStateStore {
    /// Create a new crypto state store from a client.
    pub fn new(client: &Client) -> Result<Self, StateError> {
        let state = client.platform().state();

        Ok(Self {
            master_password_unlock: state.setting(MASTER_PASSWORD_UNLOCK)?,
            wrapped_state: state.setting(WRAPPED_ACCOUNT_CRYPTO_STATE)?,
        })
    }
}

/// Persisted crypto state for CLI sessions.
///
/// Contains the encrypted key material needed to restore vault crypto across CLI restarts.
pub struct PersistedCryptoState {
    /// Master password unlock data (KDF, salt, encrypted user key).
    /// Optional because some login methods (e.g., device-only auth) may not have this.
    pub master_password_unlock: Option<MasterPasswordUnlockData>,

    /// Wrapped account cryptographic state (V1 or V2).
    /// Contains encrypted private keys and signing keys.
    pub wrapped_account_cryptographic_state: Option<WrappedAccountCryptographicState>,
}

/// Extract crypto state from sync response for CLI persistence.
///
/// Returns the encrypted key material needed to restore vault crypto across CLI restarts.
pub fn extract_from_sync(sync: &SyncResponseModel) -> Option<PersistedCryptoState> {
    let profile = sync.profile.as_ref()?;

    // Extract master password unlock data from user decryption options
    let master_password_unlock = sync
        .user_decryption
        .as_ref()
        .and_then(|ud| ud.master_password_unlock.as_ref())
        .and_then(|mpu| MasterPasswordUnlockData::try_from(mpu.as_ref()).ok());

    // Extract wrapped account cryptographic state from profile
    let wrapped_account_cryptographic_state =
        WrappedAccountCryptographicState::try_from(profile.as_ref()).ok();

    // Return Some only if we have at least one field
    if master_password_unlock.is_some() || wrapped_account_cryptographic_state.is_some() {
        Some(PersistedCryptoState {
            master_password_unlock,
            wrapped_account_cryptographic_state,
        })
    } else {
        None
    }
}

/// Persist crypto state from sync response to storage.
///
/// Call this after a successful sync to save the crypto state needed for vault unlock.
pub async fn persist(client: &Client, sync: &SyncResponseModel) -> Result<(), StateError> {
    if let Some(crypto_state) = extract_from_sync(sync) {
        let store = CryptoStateStore::new(client)?;

        // Persist master password unlock data if available
        if let Some(master_password_unlock) = crypto_state.master_password_unlock {
            store
                .master_password_unlock
                .update(master_password_unlock)
                .await?;
        }

        // Persist wrapped account crypto state if available
        if let Some(wrapped_state) = crypto_state.wrapped_account_cryptographic_state {
            store.wrapped_state.update(wrapped_state).await?;
        }

        debug!("Crypto state persisted successfully");
    } else {
        tracing::warn!("No crypto state available in sync response");
    }

    Ok(())
}

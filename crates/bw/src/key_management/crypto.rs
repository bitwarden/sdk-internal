//! Crypto state persistence for CLI sessions.
//!
//! This module handles persisting encrypted key material from sync responses
//! to allow vault unlock after CLI restart without re-authentication.
//!
//! # Persisted Keys
//!
//! - **Master Key Encrypted User Key**: Needed for master password unlock
//! - **Wrapped Account Cryptographic State**: V1/V2 private keys and signing keys

use bitwarden_api_api::models::SyncResponseModel;
use bitwarden_core::{
    Client, client::PersistedCryptoState,
    key_management::account_cryptographic_state::WrappedAccountCryptographicState,
};
use bitwarden_crypto::EncString;
use bitwarden_state::{Setting, register_setting_key};
use tracing::debug;

use crate::platform::StateError;

register_setting_key!(const MASTER_KEY_ENCRYPTED_USER_KEY: EncString = "master_key_encrypted_user_key");
register_setting_key!(const WRAPPED_ACCOUNT_CRYPTO_STATE: WrappedAccountCryptographicState = "wrapped_account_crypto_state");

/// Store for persisted crypto state.
///
/// Provides access to master key encrypted user key and wrapped account crypto state
/// settings needed for vault unlock after CLI restart.
pub struct CryptoStateStore {
    pub master_key: Setting<EncString>,
    pub wrapped_state: Setting<WrappedAccountCryptographicState>,
}

impl CryptoStateStore {
    /// Create a new crypto state store from a client.
    pub fn new(client: &Client) -> Result<Self, StateError> {
        let state = client.platform().state();

        Ok(Self {
            master_key: state.setting(MASTER_KEY_ENCRYPTED_USER_KEY)?,
            wrapped_state: state.setting(WRAPPED_ACCOUNT_CRYPTO_STATE)?,
        })
    }
}

/// Extract crypto state from sync response for CLI persistence.
///
/// Returns the encrypted key material needed to restore vault crypto across CLI restarts.
pub fn extract_from_sync(sync: &SyncResponseModel) -> Option<PersistedCryptoState> {
    let profile = sync.profile.as_ref()?;

    // Extract master key encrypted user key from user decryption options
    let master_key_encrypted_user_key = sync
        .user_decryption
        .as_ref()
        .and_then(|ud| ud.master_password_unlock.as_ref())
        .and_then(|mpu| mpu.master_key_encrypted_user_key.as_ref())
        .and_then(|key_str| key_str.parse().ok());

    // Extract wrapped account cryptographic state from profile
    let wrapped_account_cryptographic_state = profile
        .private_key
        .as_ref()
        .and_then(|pk_str| pk_str.parse().ok())
        .map(|private_key| {
            // Check if this is a V2 user by looking for account_keys
            if let Some(account_keys) = &profile.account_keys {
                // V2 user - has signing key and security state
                if let Some(signature_key_pair) = &account_keys.signature_key_pair {
                    if let Some(signing_key_str) = &signature_key_pair.wrapped_signing_key {
                        if let Ok(signing_key) = signing_key_str.parse() {
                            // Get signed public key from public_key_encryption_key_pair
                            let signed_public_key = account_keys
                                .public_key_encryption_key_pair
                                .signed_public_key
                                .as_ref()
                                .and_then(|spk_str| spk_str.parse().ok());

                            // Get security state
                            if let Some(security_state_model) = &account_keys.security_state {
                                if let Some(security_state_str) =
                                    &security_state_model.security_state
                                {
                                    if let Ok(security_state) = security_state_str.parse() {
                                        return WrappedAccountCryptographicState::V2 {
                                            private_key,
                                            signed_public_key,
                                            signing_key,
                                            security_state,
                                        };
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // V1 user - only has private key
            WrappedAccountCryptographicState::V1 { private_key }
        });

    // Return Some only if we have at least one field
    if master_key_encrypted_user_key.is_some() || wrapped_account_cryptographic_state.is_some() {
        Some(PersistedCryptoState {
            master_key_encrypted_user_key,
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

        // Persist master key encrypted user key if available
        if let Some(master_key_encrypted) = crypto_state.master_key_encrypted_user_key {
            store.master_key.update(master_key_encrypted).await?;
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

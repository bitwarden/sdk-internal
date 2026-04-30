//! Detect and fix corrupt or missing public key encryption key pairs for V1 encryption users.
//!
//! A user may have a corrupt private key that prevents key rotation or V2 encryption upgrade.
//! This module checks whether the user's public key encryption key pair needs regeneration, and if
//! so, generates a new key pair and submits it to the server via
//! `POST /accounts/key-management/regenerate-keys`.

mod regenerate;
mod should_regenerate;

use bitwarden_core::key_management::account_cryptographic_state::WrappedAccountCryptographicState;
use bitwarden_error::bitwarden_error;
use bitwarden_vault::Cipher;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use self::{
    regenerate::internal_regenerate_public_key_encryption_key_pair,
    should_regenerate::{
        internal_should_regenerate_public_key_encryption_key_pair,
        internal_should_regenerate_public_key_encryption_key_pair_with_ciphers,
    },
};
use crate::UserCryptoManagementClient;

#[derive(Debug, Error)]
#[bitwarden_error(flat)]
pub enum KeyPairRegenerationError {
    #[error("User key is not available in key store")]
    UserKeyNotAvailable,
    #[error("API call failed during key pair regeneration")]
    ApiError,
    #[error("Cryptographic error during key pair regeneration")]
    CryptoError,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl UserCryptoManagementClient {
    /// Checks whether the user's public key encryption key pair needs regeneration, and if so,
    /// generates a new key pair and submits it to the server.
    ///
    /// Returns `None` if no regeneration was needed, or the updated
    /// [`WrappedAccountCryptographicState`] if regeneration was performed. Callers should
    /// persist the returned state to their local account cryptographic state.
    ///
    /// Requires the client to be unlocked so the current user key is available in memory.
    /// Only applicable to V1 encryption accounts.
    pub async fn regenerate_public_key_encryption_key_pair_if_needed(
        &self,
    ) -> Result<Option<WrappedAccountCryptographicState>, KeyPairRegenerationError> {
        let key_store = self.client.internal.get_key_store();
        let api_client = &self.client.internal.get_api_configurations().api_client;
        let should_regenerate =
            internal_should_regenerate_public_key_encryption_key_pair(key_store, api_client)
                .await?;
        if !should_regenerate {
            return Ok(None);
        }

        let state =
            internal_regenerate_public_key_encryption_key_pair(key_store, api_client).await?;
        Ok(Some(state))
    }

    /// Checks whether the user's public key encryption key pair needs regeneration.
    ///
    /// Returns `true` if the key pair is missing, corrupt, or doesn't match the public key on
    /// the server. Returns `false` if the key pair is valid or if regeneration is not applicable
    /// (e.g., user key not available, V2 encryption account).
    pub async fn should_regenerate_public_key_encryption_key_pair(
        &self,
    ) -> Result<bool, KeyPairRegenerationError> {
        let key_store = self.client.internal.get_key_store();
        let api_client = &self.client.internal.get_api_configurations().api_client;
        internal_should_regenerate_public_key_encryption_key_pair(key_store, api_client).await
    }

    /// Variant of [`Self::regenerate_public_key_encryption_key_pair_if_needed`] that accepts
    /// pre-fetched ciphers instead of fetching them from the API.
    pub(crate) async fn regenerate_public_key_encryption_key_pair_if_needed_with_ciphers(
        &self,
        ciphers: &[Cipher],
    ) -> Result<Option<WrappedAccountCryptographicState>, KeyPairRegenerationError> {
        let key_store = self.client.internal.get_key_store();
        let api_client = &self.client.internal.get_api_configurations().api_client;
        let should_regenerate =
            internal_should_regenerate_public_key_encryption_key_pair_with_ciphers(
                key_store, api_client, ciphers,
            )
            .await?;
        if !should_regenerate {
            return Ok(None);
        }

        let state =
            internal_regenerate_public_key_encryption_key_pair(key_store, api_client).await?;
        Ok(Some(state))
    }
}

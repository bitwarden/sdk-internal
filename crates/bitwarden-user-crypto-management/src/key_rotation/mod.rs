//! Client to manage the cryptographic machinery of a user account, including key-rotation
mod crypto;
mod data;
mod partial_rotateable_keyset;
mod password_change_and_rotate_user_keys;
mod rotate_user_keys;
mod rotation_context;
mod sync;
mod unlock;
mod unlock_method;

use bitwarden_error::bitwarden_error;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    UserCryptoManagementClient,
    key_rotation::unlock::{V1EmergencyAccessMembership, V1OrganizationMembership},
};

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl UserCryptoManagementClient {
    /// Fetches the organization public keys for V1 organization memberships for the user for
    /// organizations for which reset password is enrolled.
    /// These have to be trusted manually be the user before rotating.
    pub async fn get_untrusted_organization_public_keys(
        &self,
    ) -> Result<Vec<V1OrganizationMembership>, RotateUserKeysError> {
        let api_client = &self.client.internal.get_api_configurations().api_client;
        let key_rotation_data = sync::fetch_key_rotation_data(api_client)
            .await
            .map_err(|_| RotateUserKeysError::Api)?;
        Ok(key_rotation_data.organization_memberships)
    }

    /// Fetches the emergency access public keys for V1 emergency access memberships for the user.
    /// These have to be trusted manually be the user before rotating.
    pub async fn get_untrusted_emergency_access_public_keys(
        &self,
    ) -> Result<Vec<V1EmergencyAccessMembership>, RotateUserKeysError> {
        let api_client = &self.client.internal.get_api_configurations().api_client;
        let key_rotation_data = sync::fetch_key_rotation_data(api_client)
            .await
            .map_err(|_| RotateUserKeysError::Api)?;
        Ok(key_rotation_data.emergency_access_memberships)
    }
}

/// Errors that can occur while converting key rotation API response models into their domain
/// representations.
#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum KeyRotationDataParseError {
    #[error(transparent)]
    MissingField(#[from] bitwarden_core::MissingFieldError),
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
    #[error(transparent)]
    B64(#[from] bitwarden_encoding::NotB64EncodedError),
}

#[derive(Debug, Error)]
#[bitwarden_error(flat)]
pub enum RotateUserKeysError {
    #[error("API error during key rotation")]
    Api,
    #[error("Cryptographic error during key rotation")]
    Crypto,
    #[error("Invalid public key provided during key rotation")]
    InvalidPublicKey,
    #[error("Key Connector API error during key rotation")]
    KeyConnectorApi,
    #[error("Untrusted key encountered during key rotation")]
    UntrustedKey,
    #[error("Vault contains old attachments that must be re-uploaded before key rotation")]
    OldAttachments,
}

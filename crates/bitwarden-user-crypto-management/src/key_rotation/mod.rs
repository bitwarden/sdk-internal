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
        let organizations = sync::sync_orgs(api_client)
            .await
            .map_err(|_| RotateUserKeysError::ApiError)?;
        Ok(organizations)
    }

    /// Fetches the emergency access public keys for V1 emergency access memberships for the user.
    /// These have to be trusted manually be the user before rotating.
    pub async fn get_untrusted_emergency_access_public_keys(
        &self,
    ) -> Result<Vec<V1EmergencyAccessMembership>, RotateUserKeysError> {
        let api_client = &self.client.internal.get_api_configurations().api_client;
        let emergency_access = sync::sync_emergency_access(api_client)
            .await
            .map_err(|_| RotateUserKeysError::ApiError)?;
        Ok(emergency_access)
    }
}

#[derive(Debug, Error)]
#[bitwarden_error(flat)]
pub enum RotateUserKeysError {
    #[error("API error during key rotation")]
    ApiError,
    #[error("Cryptographic error during key rotation")]
    CryptoError,
    #[error("Invalid public key provided during key rotation")]
    InvalidPublicKey,
    #[error("Untrusted key encountered during key rotation")]
    UntrustedKeyError,
    #[error("Unimplemented key rotation method")]
    UnimplementedKeyRotationMethod,
    #[error("Vault contains old attachments that must be re-uploaded before key rotation")]
    OldAttachments,
}

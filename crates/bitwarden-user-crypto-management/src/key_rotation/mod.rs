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
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    UserCryptoManagementClient,
    key_rotation::{
        rotate_user_keys::UpgradeTokenAction,
        rotation_context::organization_memberships_needing_trust,
        unlock::{V1EmergencyAccessMembership, V1OrganizationMembership},
    },
};

/// Response model for untrusted memberships, containing both organization and emergency access
/// memberships.
#[derive(Serialize, Deserialize)]
#[bitwarden_ffi::wasm_record]
pub struct UntrustedMembershipsResponse {
    emergency_access_memberships: Vec<V1EmergencyAccessMembership>,
    organization_memberships: Vec<V1OrganizationMembership>,
}

#[bitwarden_ffi::wasm_export]
impl UserCryptoManagementClient {
    /// The organization public keys the user has to confirm as trusted before a key rotation.
    ///
    /// When the rotation creates a V2 upgrade token, the list is empty. Organization admins update
    /// account recovery from that token, so the user confirms nothing. Every other rotation returns
    /// one entry per organization the user is enrolled in for account recovery.
    pub async fn get_untrusted_organization_public_keys(
        &self,
        upgrade_token_action: UpgradeTokenAction,
    ) -> Result<Vec<V1OrganizationMembership>, RotateUserKeysError> {
        let api_client = &self.client.internal.get_api_configurations().api_client;
        let key_rotation_data = sync::get_key_rotation_data(api_client)
            .await
            .map_err(|_| RotateUserKeysError::Api)?;
        Ok(organization_memberships_needing_trust(
            key_rotation_data.organization_memberships,
            upgrade_token_action,
            self.client.internal.get_key_store(),
        ))
    }

    /// Fetches the emergency access public keys for V1 emergency access memberships for the user.
    /// These have to be trusted manually be the user before rotating.
    pub async fn get_untrusted_emergency_access_public_keys(
        &self,
    ) -> Result<Vec<V1EmergencyAccessMembership>, RotateUserKeysError> {
        let api_client = &self.client.internal.get_api_configurations().api_client;
        let key_rotation_data = sync::get_key_rotation_data(api_client)
            .await
            .map_err(|_| RotateUserKeysError::Api)?;
        Ok(key_rotation_data.emergency_access_memberships)
    }

    /// The organization and emergency access public keys the user has to confirm as trusted before
    /// a key rotation.
    ///
    /// When the rotation creates a V2 upgrade token, the organization list is empty. Organization
    /// admins update account recovery from that token, so the user confirms nothing. Every other
    /// rotation returns one entry per organization the user is enrolled in for account recovery.
    ///
    /// Emergency access grantees always need a confirmation, because every rotation shares the new
    /// user key with each of them.
    pub async fn get_untrusted_memberships(
        &self,
        upgrade_token_action: UpgradeTokenAction,
    ) -> Result<UntrustedMembershipsResponse, RotateUserKeysError> {
        let api_client = &self.client.internal.get_api_configurations().api_client;
        let key_rotation_data = sync::get_key_rotation_data(api_client)
            .await
            .map_err(|_| RotateUserKeysError::Api)?;
        Ok(UntrustedMembershipsResponse {
            emergency_access_memberships: key_rotation_data.emergency_access_memberships,
            organization_memberships: organization_memberships_needing_trust(
                key_rotation_data.organization_memberships,
                upgrade_token_action,
                self.client.internal.get_key_store(),
            ),
        })
    }
}

/// Errors that can occur while converting key rotation data response models into their domain
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

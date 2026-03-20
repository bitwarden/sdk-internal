//! Client to manage the cryptographic machinery of a user account, including key-rotation
mod crypto;
mod data;
mod partial_rotateable_keyset;
mod password_change_and_rotate_user_keys;
mod rotate_user_keys;
mod sync;
mod unlock;
mod unlock_method;

use bitwarden_core::key_management::{KeyIds, SymmetricKeyId};
use bitwarden_crypto::{KeyStoreContext, PublicKey};
use bitwarden_error::bitwarden_error;
use password_change_and_rotate_user_keys::post_password_change_and_rotate_user_keys;
use rotate_user_keys::post_rotate_user_keys;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    UserCryptoManagementClient,
    key_rotation::unlock::{V1EmergencyAccessMembership, V1OrganizationMembership},
};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum KeyRotationMethod {
    // Master password user, key rotation without a password change.
    Password {
        password: String,
    },
    /// Key connector user, key rotation without a password change.
    /// NOTE: This is not yet implemented, and will panic
    KeyConnector,
    /// TDE user, key rotation without a password change.
    /// NOTE: This is not yet implemented, and will panic
    Tde,
}

#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct RotateUserKeysRequest {
    pub key_rotation_method: KeyRotationMethod,
    pub trusted_emergency_access_public_keys: Vec<PublicKey>,
    pub trusted_organization_public_keys: Vec<PublicKey>,
}

#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PasswordChangeAndRotateUserKeysRequest {
    pub old_password: String,
    pub password: String,
    pub hint: Option<String>,
    pub trusted_emergency_access_public_keys: Vec<PublicKey>,
    pub trusted_organization_public_keys: Vec<PublicKey>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl UserCryptoManagementClient {
    /// Combines a password change and user key rotation into a single request.
    pub async fn password_change_and_rotate_user_keys(
        &self,
        request: PasswordChangeAndRotateUserKeysRequest,
    ) -> Result<(), RotateUserKeysError> {
        let api_client = &self.client.internal.get_api_configurations().api_client;
        post_password_change_and_rotate_user_keys(
            self,
            api_client,
            request.trusted_organization_public_keys.as_slice(),
            request.trusted_emergency_access_public_keys.as_slice(),
            request.old_password,
            request.password,
            request.hint,
        )
        .await
    }

    /// Rotates the user's encryption keys.
    pub async fn rotate_user_keys(
        &self,
        request: RotateUserKeysRequest,
    ) -> Result<(), RotateUserKeysError> {
        match request.key_rotation_method {
            KeyRotationMethod::KeyConnector => {
                return Err(RotateUserKeysError::UnimplementedKeyRotationMethod);
            }
            KeyRotationMethod::Tde => {
                return Err(RotateUserKeysError::UnimplementedKeyRotationMethod);
            }
            // Password based rotation is implemented.
            _ => {}
        }

        let api_client = &self.client.internal.get_api_configurations().api_client;
        post_rotate_user_keys(
            self,
            api_client,
            request.trusted_organization_public_keys.as_slice(),
            request.trusted_emergency_access_public_keys.as_slice(),
            request.key_rotation_method,
        )
        .await
    }

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
}

struct UntrustedKeyError;

fn filter_trusted_organization(
    org: &[V1OrganizationMembership],
    trusted_orgs: &[PublicKey],
) -> Result<Vec<V1OrganizationMembership>, UntrustedKeyError> {
    org.iter()
        .map(|o| {
            let is_trusted = trusted_orgs.iter().any(|tk| tk == &o.public_key);
            if !is_trusted {
                warn!(
                    "Filtering out untrusted organization with id={}",
                    o.organization_id
                );
                Err(UntrustedKeyError)
            } else {
                Ok(o.clone())
            }
        })
        .collect::<Result<Vec<V1OrganizationMembership>, UntrustedKeyError>>()
}

fn filter_trusted_emergency_access(
    ea: &[V1EmergencyAccessMembership],
    trusted_emergency_access_user_public_keys: &[PublicKey],
) -> Result<Vec<V1EmergencyAccessMembership>, UntrustedKeyError> {
    ea.iter()
        .map(|e| {
            let is_trusted = trusted_emergency_access_user_public_keys
                .iter()
                .any(|tk| tk == &e.public_key);
            if !is_trusted {
                warn!(
                    "Filtering out untrusted emergency access membership with id={}",
                    e.id
                );
                Err(UntrustedKeyError)
            } else {
                Ok(e.to_owned())
            }
        })
        .collect::<Result<Vec<V1EmergencyAccessMembership>, UntrustedKeyError>>()
}

struct RotationContext {
    v1_organization_memberships: Vec<V1OrganizationMembership>,
    v1_emergency_access_memberships: Vec<V1EmergencyAccessMembership>,
    current_user_key_id: SymmetricKeyId,
    new_user_key_id: SymmetricKeyId,
}

fn prepare_rotation_context(
    sync: &sync::SyncedAccountData,
    trusted_organization_public_keys: &[PublicKey],
    trusted_emergency_access_public_keys: &[PublicKey],
    ctx: &mut KeyStoreContext<KeyIds>,
) -> Result<RotationContext, RotateUserKeysError> {
    let v1_organization_memberships = filter_trusted_organization(
        sync.organization_memberships.as_slice(),
        trusted_organization_public_keys,
    )
    .map_err(|_| RotateUserKeysError::UntrustedKeyError)?;

    let v1_emergency_access_memberships = filter_trusted_emergency_access(
        sync.emergency_access_memberships.as_slice(),
        trusted_emergency_access_public_keys,
    )
    .map_err(|_| RotateUserKeysError::UntrustedKeyError)?;

    info!(
        "Existing user cryptographic version {:?}",
        sync.wrapped_account_cryptographic_state
    );
    let current_user_key_id = SymmetricKeyId::User;

    debug!("Generating new xchacha20-poly1305 user key for key rotation");
    let new_user_key_id =
        ctx.make_symmetric_key(bitwarden_crypto::SymmetricKeyAlgorithm::XChaCha20Poly1305);

    Ok(RotationContext {
        v1_organization_memberships,
        v1_emergency_access_memberships,
        current_user_key_id,
        new_user_key_id,
    })
}

//! Client to manage the cryptographic machinery of a user account, including key-rotation
mod crypto;
mod data;
mod partial_rotateable_keyset;
mod rotation_context;
mod sync;
mod unlock;

use bitwarden_api_api::models::RotateUserAccountKeysAndDataRequestModel;
use bitwarden_core::key_management::MasterPasswordAuthenticationData;
use bitwarden_crypto::PublicKey;
use bitwarden_error::bitwarden_error;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, info_span};
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    UserCryptoManagementClient,
    key_rotation::{
        crypto::rotate_account_cryptographic_state,
        data::reencrypt_data,
        rotation_context::make_rotation_context,
        unlock::{
            ReencryptUnlockInput, V1EmergencyAccessMembership, V1OrganizationMembership,
            reencrypt_unlock,
        },
    },
};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum MasterkeyUnlockMethod {
    Password {
        old_password: String,
        password: String,
        hint: Option<String>,
    },
    /// Unlock via key-connector.
    /// NOTE: This is not yet implemented, and will panic
    KeyConnector,
    /// No masterkey-based unlock.
    /// NOTE: This is not yet implemented, and will panic
    None,
}

#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct RotateUserKeysRequest {
    pub master_key_unlock_method: MasterkeyUnlockMethod,
    pub trusted_emergency_access_public_keys: Vec<PublicKey>,
    pub trusted_organization_public_keys: Vec<PublicKey>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl UserCryptoManagementClient {
    /// Rotates the user's encryption keys. The user must have a master-password.
    pub async fn rotate_user_keys(
        &self,
        request: RotateUserKeysRequest,
    ) -> Result<(), RotateUserKeysError> {
        let api_client = &self.client.internal.get_api_configurations().api_client;

        post_rotate_user_keys(
            self,
            api_client,
            request.trusted_organization_public_keys.as_slice(),
            request.trusted_emergency_access_public_keys.as_slice(),
            request.master_key_unlock_method,
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
}

async fn post_rotate_user_keys(
    registration_client: &UserCryptoManagementClient,
    api_client: &bitwarden_api_api::apis::ApiClient,

    trusted_organization_public_keys: &[PublicKey],
    trusted_emergency_access_public_keys: &[PublicKey],

    master_key_unlock_method: MasterkeyUnlockMethod,
) -> Result<(), RotateUserKeysError> {
    let _span = info_span!("rotate_user_keys").entered();
    let sync = sync::sync_current_account_data(api_client)
        .await
        .map_err(|_| RotateUserKeysError::ApiError)?;

    let key_store = registration_client.client.internal.get_key_store();
    // Create a separate scope so that the mutable context is not held across the await point
    let request = {
        let mut ctx = key_store.context_mut();

        let rotation_context = make_rotation_context(
            &sync,
            trusted_organization_public_keys,
            trusted_emergency_access_public_keys,
            &mut ctx,
        )?;

        info!("Rotating account cryptographic state for user key rotation");
        let account_keys_model = rotate_account_cryptographic_state(
            &sync.wrapped_account_cryptographic_state,
            &rotation_context.current_user_key_id,
            &rotation_context.new_user_key_id,
            &mut ctx,
        )
        .map_err(|_| RotateUserKeysError::CryptoError)?;

        info!("Re-encrypting account data for user key rotation");
        let account_data_model = reencrypt_data(
            sync.folders.as_slice(),
            sync.ciphers.as_slice(),
            sync.sends.as_slice(),
            rotation_context.current_user_key_id,
            rotation_context.new_user_key_id,
            &mut ctx,
        )
        .map_err(|_| RotateUserKeysError::CryptoError)?;

        info!("Re-encrypting account unlock data for user key rotation");
        let unlock_data_model = reencrypt_unlock(
            ReencryptUnlockInput {
                master_key_unlock_method: match master_key_unlock_method {
                    MasterkeyUnlockMethod::Password {
                        old_password: _,
                        ref password,
                        ref hint,
                    } => {
                        let (kdf, salt) = sync
                            .kdf_and_salt
                            .clone()
                            .ok_or(RotateUserKeysError::ApiError)?;
                        unlock::MasterkeyUnlockMethod::Password {
                            password: password.to_owned(),
                            hint: hint.to_owned(),
                            kdf,
                            salt,
                        }
                    }
                    MasterkeyUnlockMethod::KeyConnector => {
                        unlock::MasterkeyUnlockMethod::KeyConnector
                    }
                    MasterkeyUnlockMethod::None => unlock::MasterkeyUnlockMethod::None,
                },
                trusted_devices: sync.trusted_devices,
                webauthn_credentials: sync.passkeys,
                trusted_organization_keys: rotation_context.v1_organization_memberships,
                trusted_emergency_access_keys: rotation_context.v1_emergency_access_memberships,
            },
            rotation_context.current_user_key_id,
            rotation_context.new_user_key_id,
            &mut ctx,
        )
        .map_err(|_| RotateUserKeysError::CryptoError)?;

        let old_masterpassword_authentication_data = match master_key_unlock_method {
            MasterkeyUnlockMethod::Password {
                old_password,
                password: _,
                hint: _,
            } => {
                let (kdf, salt) = sync
                    .kdf_and_salt
                    .clone()
                    .ok_or(RotateUserKeysError::ApiError)?;
                let authentication_data =
                    MasterPasswordAuthenticationData::derive(&old_password, &kdf, &salt)
                        .map_err(|_| RotateUserKeysError::CryptoError)?;
                Some(authentication_data)
            }
            MasterkeyUnlockMethod::KeyConnector => {
                tracing::error!("Key-connector based key rotation is not yet implemented");
                None
            }
            MasterkeyUnlockMethod::None => {
                tracing::error!(
                    "Key-rotation without master-key based unlock is not supported yet"
                );
                None
            }
        }
        .expect("Master password authentication data is required for password-based key rotation");
        RotateUserAccountKeysAndDataRequestModel {
            old_master_key_authentication_hash: Some(
                old_masterpassword_authentication_data
                    .master_password_authentication_hash
                    .to_string(),
            ),
            account_keys: Box::new(account_keys_model),
            account_data: Box::new(account_data_model),
            account_unlock_data: Box::new(unlock_data_model),
        }
    };

    info!("Posting rotated user account keys and data to server");
    registration_client
        .client
        .internal
        .get_api_configurations()
        .api_client
        .accounts_key_management_api()
        .password_change_and_rotate_user_account_keys(Some(request))
        .await
        .map_err(|_| RotateUserKeysError::ApiError)?;
    info!("Successfully rotated user account keys and data");
    Ok(())
}

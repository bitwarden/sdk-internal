//! Client to manage the cryptographic machinery of a user account, including key-rotation
mod crypto;
mod data;
mod partial_rotateable_keyset;
mod sync;
mod unlock;

use bitwarden_api_api::models::RotateUserAccountKeysAndDataRequestModel;
use bitwarden_core::key_management::{MasterPasswordAuthenticationData, SymmetricKeyId};
use bitwarden_crypto::PublicKey;
use bitwarden_error::bitwarden_error;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, info_span, warn};
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    UserCryptoManagementClient,
    key_rotation::{
        crypto::rotate_account_cryptographic_state_to_request_model,
        data::reencrypt_data,
        unlock::{
            ReencryptCommonUnlockDataInput, ReencryptMasterPasswordChangeAndUnlockInput,
            V1EmergencyAccessMembership, V1OrganizationMembership,
            reencrypt_master_password_change_unlock_data,
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

        // Filter organization memberships and emergency access memberships to only include trusted
        // keys
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

        info!("Rotating account cryptographic state for user key rotation");
        let account_keys_model = rotate_account_cryptographic_state_to_request_model(
            &sync.wrapped_account_cryptographic_state,
            &current_user_key_id,
            &new_user_key_id,
            &mut ctx,
        )
        .map_err(|_| RotateUserKeysError::CryptoError)?;

        info!("Re-encrypting account data for user key rotation");
        let account_data_model = reencrypt_data(
            sync.folders.as_slice(),
            sync.ciphers.as_slice(),
            sync.sends.as_slice(),
            current_user_key_id,
            new_user_key_id,
            &mut ctx,
        )
        .map_err(|_| RotateUserKeysError::CryptoError)?;

        info!("Re-encrypting account unlock data for user key rotation");
        let MasterkeyUnlockMethod::Password {
            old_password,
            password,
            hint,
        } = master_key_unlock_method
        else {
            return Err(RotateUserKeysError::UnimplementedKeyRotationMethod);
        };
        let (kdf, salt) = sync.kdf_and_salt.ok_or(RotateUserKeysError::ApiError)?;
        let unlock_data_model = reencrypt_master_password_change_unlock_data(
            ReencryptMasterPasswordChangeAndUnlockInput {
                password,
                hint,
                kdf: kdf.clone(),
                salt: salt.clone(),
                common_unlock_data: ReencryptCommonUnlockDataInput {
                    trusted_devices: sync.trusted_devices,
                    webauthn_credentials: sync.passkeys,
                    trusted_organization_keys: v1_organization_memberships,
                    trusted_emergency_access_keys: v1_emergency_access_memberships,
                },
            },
            current_user_key_id,
            new_user_key_id,
            &mut ctx,
        )
        .map_err(|_| RotateUserKeysError::CryptoError)?;

        let old_master_password_authentication_data =
            MasterPasswordAuthenticationData::derive(&old_password, &kdf, &salt)
                .map_err(|_| RotateUserKeysError::CryptoError)?;

        RotateUserAccountKeysAndDataRequestModel {
            old_master_key_authentication_hash: Some(
                old_master_password_authentication_data
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

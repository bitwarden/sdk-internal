//! Functionality for rotating user keys, bundled with a password change.
use bitwarden_api_api::models::RotateUserAccountKeysAndDataRequestModel;
use bitwarden_core::key_management::MasterPasswordAuthenticationData;
use bitwarden_crypto::PublicKey;
use tracing::{info, info_span};

use super::RotateUserKeysError;
use crate::{
    UserCryptoManagementClient,
    key_rotation::{
        crypto::rotate_account_cryptographic_state_to_request_model,
        data::reencrypt_data,
        prepare_rotation_context,
        unlock::{
            ReencryptCommonUnlockDataInput, ReencryptMasterPasswordChangeAndUnlockInput,
            reencrypt_master_password_change_unlock_data,
        },
    },
};

pub(crate) async fn post_password_change_and_rotate_user_keys(
    registration_client: &UserCryptoManagementClient,
    api_client: &bitwarden_api_api::apis::ApiClient,
    trusted_organization_public_keys: &[PublicKey],
    trusted_emergency_access_public_keys: &[PublicKey],
    old_password: String,
    password: String,
    hint: Option<String>,
) -> Result<(), RotateUserKeysError> {
    let _span = info_span!("post_password_change_and_rotate_user_keys").entered();
    let sync = super::sync::sync_current_account_data(api_client)
        .await
        .map_err(|_| RotateUserKeysError::ApiError)?;

    let key_store = registration_client.client.internal.get_key_store();
    // Create a separate scope so that the mutable context is not held across the await point
    let request = {
        let mut ctx = key_store.context_mut();

        let rotation_context = prepare_rotation_context(
            &sync,
            trusted_organization_public_keys,
            trusted_emergency_access_public_keys,
            &mut ctx,
        )?;

        info!("Rotating account cryptographic state for user key rotation");
        let account_keys_model = rotate_account_cryptographic_state_to_request_model(
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
        let (kdf, salt) = sync
            .kdf_and_salt
            .clone()
            .ok_or(RotateUserKeysError::ApiError)?;
        let unlock_data_model = reencrypt_master_password_change_unlock_data(
            ReencryptMasterPasswordChangeAndUnlockInput {
                password: password.clone(),
                hint: hint.clone(),
                kdf,
                salt,
                common_unlock_data: ReencryptCommonUnlockDataInput {
                    trusted_devices: sync.trusted_devices,
                    webauthn_credentials: sync.passkeys,
                    trusted_organization_keys: rotation_context.v1_organization_memberships,
                    trusted_emergency_access_keys: rotation_context.v1_emergency_access_memberships,
                },
            },
            rotation_context.current_user_key_id,
            rotation_context.new_user_key_id,
            &mut ctx,
        )
        .map_err(|_| RotateUserKeysError::CryptoError)?;

        let old_master_password_authentication_data = {
            let (kdf, salt) = sync
                .kdf_and_salt
                .clone()
                .ok_or(RotateUserKeysError::ApiError)?;
            MasterPasswordAuthenticationData::derive(&old_password, &kdf, &salt)
                .map_err(|_| RotateUserKeysError::CryptoError)?
        };

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

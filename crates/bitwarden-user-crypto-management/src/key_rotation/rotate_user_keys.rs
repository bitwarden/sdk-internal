//! Functionality for rotating user keys, no password change.

use bitwarden_api_api::models::RotateUserKeysRequestModel;
use bitwarden_crypto::PublicKey;
use tracing::{info, info_span};

use super::{KeyRotationMethod, RotateUserKeysError};
use crate::{
    UserCryptoManagementClient,
    key_rotation::{
        crypto::rotate_account_cryptographic_state_to_wrapped_model,
        data::reencrypt_data,
        prepare_rotation_context,
        unlock::{ReencryptCommonUnlockDataInput, reencrypt_common_unlock_data},
        unlock_method::{UnlockMethodInput, reencrypt_unlock_method_data},
    },
};

pub(crate) async fn post_rotate_user_keys(
    registration_client: &UserCryptoManagementClient,
    api_client: &bitwarden_api_api::apis::ApiClient,
    trusted_organization_public_keys: &[PublicKey],
    trusted_emergency_access_public_keys: &[PublicKey],
    key_rotation_method: KeyRotationMethod,
) -> Result<(), RotateUserKeysError> {
    let _span = info_span!("post_rotate_user_keys").entered();
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
        let wrapped_account_cryptographic_state_request_model =
            rotate_account_cryptographic_state_to_wrapped_model(
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

        info!("Re-encrypting account unlock method for user key rotation");
        let unlock_method_input =
            UnlockMethodInput::from_key_rotation_method(key_rotation_method, &sync)
                .map_err(|_| RotateUserKeysError::ApiError)?;
        let unlock_method_data = reencrypt_unlock_method_data(
            unlock_method_input,
            rotation_context.new_user_key_id,
            &mut ctx,
        )
        .map_err(|_| RotateUserKeysError::CryptoError)?;

        info!("Re-encrypting account common unlock data for user key rotation");
        let common_unlock_data = reencrypt_common_unlock_data(
            ReencryptCommonUnlockDataInput {
                trusted_organization_keys: rotation_context.v1_organization_memberships,
                trusted_emergency_access_keys: rotation_context.v1_emergency_access_memberships,
                webauthn_credentials: sync.passkeys,
                trusted_devices: sync.trusted_devices,
            },
            rotation_context.current_user_key_id,
            rotation_context.new_user_key_id,
            &mut ctx,
        )
        .map_err(|_| RotateUserKeysError::CryptoError)?;

        RotateUserKeysRequestModel {
            wrapped_account_cryptographic_state: Box::new(
                wrapped_account_cryptographic_state_request_model,
            ),
            account_data: Box::new(account_data_model),
            unlock_data: Box::new(common_unlock_data),
            unlock_method_data: Box::new(unlock_method_data),
        }
    };

    info!("Posting rotated user account keys and data to server");
    registration_client
        .client
        .internal
        .get_api_configurations()
        .api_client
        .accounts_key_management_api()
        .rotate_user_keys(Some(request))
        .await
        .map_err(|_| RotateUserKeysError::ApiError)?;
    info!("Successfully rotated user account keys and data");
    Ok(())
}

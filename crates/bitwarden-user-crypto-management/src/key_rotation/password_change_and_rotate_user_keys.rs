//! Functionality for rotating user keys, bundled with a password change.
use bitwarden_api_api::models::RotateUserAccountKeysAndDataRequestModel;
use bitwarden_core::key_management::{KeySlotIds, MasterPasswordAuthenticationData};
use bitwarden_crypto::{KeyStore, PublicKey};
use serde::{Deserialize, Serialize};
use tracing::{info, instrument};
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    UserCryptoManagementClient,
    key_rotation::{
        RotateUserKeysError,
        crypto::rotate_account_cryptographic_state_to_request_model,
        data::reencrypt_data,
        rotation_context::make_rotation_context,
        sync::{SyncedAccountData, sync_current_account_data},
        unlock::{
            ReencryptCommonUnlockDataInput, ReencryptMasterPasswordChangeAndUnlockInput,
            reencrypt_master_password_change_unlock_data,
        },
    },
};

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
    ///
    /// Before rotating, this checks whether the user's public key encryption key pair needs
    /// regeneration and fixes it if necessary. This ensures that key rotation can proceed even
    /// if the existing private key is corrupt.
    pub async fn password_change_and_rotate_user_keys(
        &self,
        request: PasswordChangeAndRotateUserKeysRequest,
    ) -> Result<(), RotateUserKeysError> {
        let api_client = &self.client.internal.get_api_configurations().api_client;
        let key_store = self.client.internal.get_key_store();

        let sync = sync_current_account_data(api_client)
            .await
            .map_err(|_| RotateUserKeysError::ApiError)?;

        self.regenerate_public_key_encryption_key_pair_if_needed_with_ciphers(&sync.ciphers)
            .await
            .map_err(|_| RotateUserKeysError::CryptoError)?;

        internal_password_change_and_rotate_user_keys(key_store, api_client, request, sync).await
    }
}

#[instrument(
    name = "password_change_and_rotate_user_keys",
    level = "info",
    skip_all,
    err
)]
async fn internal_password_change_and_rotate_user_keys(
    key_store: &KeyStore<KeySlotIds>,
    api_client: &bitwarden_api_api::apis::ApiClient,
    request: PasswordChangeAndRotateUserKeysRequest,
    sync: SyncedAccountData,
) -> Result<(), RotateUserKeysError> {
    // Create a separate scope so that the mutable context is not held across the await point
    let post_request = {
        let mut ctx = key_store.context_mut();

        let rotation_context = make_rotation_context(
            &sync,
            request.trusted_organization_public_keys.as_slice(),
            request.trusted_emergency_access_public_keys.as_slice(),
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
        let (kdf, salt) = sync.kdf_and_salt.ok_or(RotateUserKeysError::ApiError)?;
        let unlock_data_model = reencrypt_master_password_change_unlock_data(
            ReencryptMasterPasswordChangeAndUnlockInput {
                password: request.password,
                hint: request.hint,
                kdf: kdf.clone(),
                salt: salt.clone(),
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

        let old_master_password_authentication_data =
            MasterPasswordAuthenticationData::derive(&request.old_password, &kdf, &salt)
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
    api_client
        .accounts_key_management_api()
        .password_change_and_rotate_user_account_keys(Some(post_request))
        .await
        .map_err(|_| RotateUserKeysError::ApiError)?;
    info!("Successfully rotated user account keys and data");
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::apis::ApiClient;
    use bitwarden_core::key_management::{
        KeySlotIds, SymmetricKeySlotId,
        account_cryptographic_state::WrappedAccountCryptographicState,
    };
    use bitwarden_crypto::{Kdf, KeyStore, PublicKeyEncryptionAlgorithm, SymmetricKeyAlgorithm};

    use super::*;

    fn make_test_key_store_and_synced_data() -> (KeyStore<KeySlotIds>, SyncedAccountData) {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let wrapped_private_key = {
            let mut ctx = store.context_mut();
            let user_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            let _ = ctx.persist_symmetric_key(user_key, SymmetricKeySlotId::User);
            let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
            ctx.wrap_private_key(SymmetricKeySlotId::User, private_key)
                .unwrap()
        };

        let sync = SyncedAccountData {
            wrapped_account_cryptographic_state: WrappedAccountCryptographicState::V1 {
                private_key: wrapped_private_key,
            },
            folders: vec![],
            ciphers: vec![],
            sends: vec![],
            emergency_access_memberships: vec![],
            organization_memberships: vec![],
            trusted_devices: vec![],
            passkeys: vec![],
            kdf_and_salt: Some((
                Kdf::PBKDF2 {
                    iterations: std::num::NonZeroU32::new(600000).unwrap(),
                },
                "test_salt".to_string(),
            )),
        };

        (store, sync)
    }

    #[tokio::test]
    async fn test_password_change_and_rotate_user_keys_missing_kdf_returns_api_error() {
        let (key_store, mut sync) = make_test_key_store_and_synced_data();
        sync.kdf_and_salt = None;

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_password_change_and_rotate_user_account_keys()
                .never();
        });

        let result = internal_password_change_and_rotate_user_keys(
            &key_store,
            &api_client,
            PasswordChangeAndRotateUserKeysRequest {
                old_password: "old_password".to_string(),
                password: "new_password".to_string(),
                hint: None,
                trusted_organization_public_keys: vec![],
                trusted_emergency_access_public_keys: vec![],
            },
            sync,
        )
        .await;

        assert!(matches!(result, Err(RotateUserKeysError::ApiError)));
        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_key_management_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_password_change_and_rotate_user_keys_success() {
        let (key_store, sync) = make_test_key_store_and_synced_data();
        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_password_change_and_rotate_user_account_keys()
                .once()
                .returning(|_| Ok(()));
        });

        let result = internal_password_change_and_rotate_user_keys(
            &key_store,
            &api_client,
            PasswordChangeAndRotateUserKeysRequest {
                old_password: "old_password".to_string(),
                password: "new_password".to_string(),
                hint: None,
                trusted_organization_public_keys: vec![],
                trusted_emergency_access_public_keys: vec![],
            },
            sync,
        )
        .await;

        assert!(result.is_ok());
        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_key_management_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_password_change_and_rotate_user_keys_post_api_failure_returns_api_error() {
        let (key_store, sync) = make_test_key_store_and_synced_data();
        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_password_change_and_rotate_user_account_keys()
                .once()
                .returning(|_| {
                    Err(bitwarden_api_api::apis::Error::Serde(
                        serde_json::Error::io(std::io::Error::other("API error")),
                    ))
                });
        });

        let result = internal_password_change_and_rotate_user_keys(
            &key_store,
            &api_client,
            PasswordChangeAndRotateUserKeysRequest {
                old_password: "old_password".to_string(),
                password: "new_password".to_string(),
                hint: None,
                trusted_organization_public_keys: vec![],
                trusted_emergency_access_public_keys: vec![],
            },
            sync,
        )
        .await;

        assert!(matches!(result, Err(RotateUserKeysError::ApiError)));
        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_key_management_api.checkpoint();
        }
    }
}

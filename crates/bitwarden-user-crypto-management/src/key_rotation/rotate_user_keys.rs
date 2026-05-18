//! Client implementation for rotating user keys without a password change.
use bitwarden_api_api::models::RotateUserKeysRequestModel;
use bitwarden_core::key_management::{
    KeySlotIds, account_cryptographic_state::WrappedAccountCryptographicState,
};
use bitwarden_crypto::{KeyConnectorKey, KeyStore, PublicKey};
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
        crypto::rotate_account_cryptographic_state_to_wrapped_model,
        data::{check_for_old_attachments, reencrypt_data},
        rotation_context::make_rotation_context,
        sync::{SyncedAccountData, sync_current_account_data},
        unlock::{ReencryptCommonUnlockDataInput, reencrypt_common_unlock_data},
        unlock_method::{PrimaryUnlockMethod, reencrypt_unlock_method_data},
    },
};

#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum KeyRotationMethod {
    /// Master password user, key rotation without a password change.
    Password { password: String },
    /// Key Connector user, key rotation without a password change.
    KeyConnector { key_connector_url: String },
    /// TDE user, key rotation without a password change.
    /// NOTE: This is not yet implemented and will return a
    /// RotateUserKeysError::UnimplementedKeyRotationMethod error if used.
    Tde,
}

#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum UpgradeTokenAction {
    /// Skip creating and sending an upgrade token to the server. This will be the default behavior
    /// if the field is omitted.
    Skip,
    /// Creates an upgrade token for V1 -> V2 key rotations.
    /// For V2 -> V2 rotations, no upgrade token is needed.
    CreateIfNeeded,
}

#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct RotateUserKeysRequest {
    pub key_rotation_method: KeyRotationMethod,
    pub trusted_emergency_access_public_keys: Vec<PublicKey>,
    pub trusted_organization_public_keys: Vec<PublicKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "wasm", tsify(optional))]
    pub upgrade_token_action: Option<UpgradeTokenAction>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl UserCryptoManagementClient {
    /// Rotates the user's encryption keys without a password change.
    pub async fn rotate_user_keys(
        &self,
        request: RotateUserKeysRequest,
    ) -> Result<(), RotateUserKeysError> {
        let api_client = &self.client.internal.get_api_configurations().api_client;
        let key_store = self.client.internal.get_key_store();

        let sync = sync_current_account_data(api_client)
            .await
            .map_err(|_| RotateUserKeysError::Api)?;

        let wrapped_account_cryptographic_state = self
            .regenerate_public_key_encryption_key_pair_if_needed_with_ciphers(&sync.ciphers)
            .await
            .map_err(|_| RotateUserKeysError::Crypto)?
            .unwrap_or_else(|| sync.wrapped_account_cryptographic_state.clone());

        let key_connector_api_client =
            if let KeyRotationMethod::KeyConnector { key_connector_url } =
                &request.key_rotation_method
            {
                Some(
                    self.client
                        .internal
                        .get_key_connector_client(key_connector_url.clone()),
                )
            } else {
                None
            };

        internal_rotate_user_keys(
            key_store,
            api_client,
            key_connector_api_client.as_ref(),
            request,
            wrapped_account_cryptographic_state,
            sync,
        )
        .await
    }
}

#[instrument(name = "rotate_user_keys", level = "info", skip_all, err)]
async fn internal_rotate_user_keys(
    key_store: &KeyStore<KeySlotIds>,
    api_client: &bitwarden_api_api::apis::ApiClient,
    key_connector_api_client: Option<&bitwarden_api_key_connector::apis::ApiClient>,
    request: RotateUserKeysRequest,
    wrapped_account_cryptographic_state: WrappedAccountCryptographicState,
    sync: SyncedAccountData,
) -> Result<(), RotateUserKeysError> {
    if matches!(request.key_rotation_method, KeyRotationMethod::Tde) {
        return Err(RotateUserKeysError::UnimplementedKeyRotationMethod);
    }

    // Fail early if any cipher has old attachments that would become irrecoverable
    check_for_old_attachments(&sync.ciphers)?;

    // For Key Connector users, fetch the existing KC key from the KC server.
    // This must happen before the synchronous key store scope below.
    let key_connector_key = if matches!(
        request.key_rotation_method,
        KeyRotationMethod::KeyConnector { .. }
    ) {
        let key_connector_client =
            key_connector_api_client.ok_or(RotateUserKeysError::KeyConnectorApi)?;
        info!("Fetching Key Connector key for key rotation");
        let response = key_connector_client
            .user_keys_api()
            .get_user_key()
            .await
            .map_err(|_| RotateUserKeysError::KeyConnectorApi)?;
        let key_connector_key =
            KeyConnectorKey::try_from(response).map_err(|_| RotateUserKeysError::Crypto)?;
        Some(key_connector_key)
    } else {
        None
    };

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
        let wrapped_account_cryptographic_state_request_model =
            rotate_account_cryptographic_state_to_wrapped_model(
                &wrapped_account_cryptographic_state,
                &rotation_context.current_user_key_id,
                &rotation_context.new_user_key_id,
                &mut ctx,
            )
            .map_err(|_| RotateUserKeysError::Crypto)?;

        info!("Re-encrypting account data for user key rotation");
        let account_data_model = reencrypt_data(
            sync.folders.as_slice(),
            sync.ciphers.as_slice(),
            sync.sends.as_slice(),
            rotation_context.current_user_key_id,
            rotation_context.new_user_key_id,
            &mut ctx,
        )
        .map_err(|_| RotateUserKeysError::Crypto)?;

        info!("Re-encrypting account primary unlock method for user key rotation");
        let unlock_method_input = PrimaryUnlockMethod::from_key_rotation_method(
            request.key_rotation_method,
            &sync,
            key_connector_key,
        )?;
        let unlock_method_data = reencrypt_unlock_method_data(
            unlock_method_input,
            rotation_context.new_user_key_id,
            &mut ctx,
        )
        .map_err(|_| RotateUserKeysError::Crypto)?;

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
            request
                .upgrade_token_action
                .unwrap_or(UpgradeTokenAction::Skip),
            &mut ctx,
        )
        .map_err(|_| RotateUserKeysError::Crypto)?;

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
    api_client
        .accounts_key_management_api()
        .rotate_user_keys(Some(post_request))
        .await
        .map_err(|_| RotateUserKeysError::Api)?;
    info!("Successfully rotated user account keys and data");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitwarden_api_api::apis::ApiClient;
    use bitwarden_core::key_management::{
        KeySlotIds, SymmetricKeySlotId,
        account_cryptographic_state::WrappedAccountCryptographicState,
    };
    use bitwarden_crypto::{Kdf, KeyStore, PublicKeyEncryptionAlgorithm, SymmetricKeyAlgorithm};
    use bitwarden_vault::{Attachment, Cipher, CipherType};
    use chrono::DateTime;

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
    async fn test_rotate_user_keys_tde_returns_unimplemented() {
        let (key_store, sync) = make_test_key_store_and_synced_data();
        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_rotate_user_keys()
                .never();
        });

        let result = internal_rotate_user_keys(
            &key_store,
            &api_client,
            None,
            RotateUserKeysRequest {
                key_rotation_method: KeyRotationMethod::Tde,
                trusted_organization_public_keys: vec![],
                trusted_emergency_access_public_keys: vec![],
                upgrade_token_action: None,
            },
            sync.wrapped_account_cryptographic_state.clone(),
            sync,
        )
        .await;

        assert!(matches!(
            result,
            Err(RotateUserKeysError::UnimplementedKeyRotationMethod)
        ));
        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_key_management_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_rotate_user_keys_master_password_success() {
        let (key_store, sync) = make_test_key_store_and_synced_data();
        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_rotate_user_keys()
                .once()
                .returning(|_| Ok(()));
        });

        let result = internal_rotate_user_keys(
            &key_store,
            &api_client,
            None,
            RotateUserKeysRequest {
                key_rotation_method: KeyRotationMethod::Password {
                    password: "test_password".to_string(),
                },
                trusted_organization_public_keys: vec![],
                trusted_emergency_access_public_keys: vec![],
                upgrade_token_action: None,
            },
            sync.wrapped_account_cryptographic_state.clone(),
            sync,
        )
        .await;

        assert!(result.is_ok());
        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_key_management_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_rotate_user_keys_post_api_failure_returns_api_error() {
        let (key_store, sync) = make_test_key_store_and_synced_data();
        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_rotate_user_keys()
                .once()
                .returning(|_| {
                    Err(serde_json::Error::io(std::io::Error::other("API error")).into())
                });
        });

        let result = internal_rotate_user_keys(
            &key_store,
            &api_client,
            None,
            RotateUserKeysRequest {
                key_rotation_method: KeyRotationMethod::Password {
                    password: "test_password".to_string(),
                },
                trusted_organization_public_keys: vec![],
                trusted_emergency_access_public_keys: vec![],
                upgrade_token_action: None,
            },
            sync.wrapped_account_cryptographic_state.clone(),
            sync,
        )
        .await;

        assert!(matches!(result, Err(RotateUserKeysError::Api)));
        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_key_management_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_rotate_user_keys_upgrade_token_action_none_omits_token() {
        let (key_store, sync) = make_test_key_store_and_synced_data();
        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_rotate_user_keys()
                .once()
                .returning(|req| {
                    let req = req.expect("request body should be present");
                    assert!(
                        req.unlock_data.v2_upgrade_token.is_none(),
                        "upgrade_token_action None, should omit the v2_upgrade_token"
                    );
                    Ok(())
                });
        });

        let result = internal_rotate_user_keys(
            &key_store,
            &api_client,
            None,
            RotateUserKeysRequest {
                key_rotation_method: KeyRotationMethod::Password {
                    password: "test_password".to_string(),
                },
                trusted_organization_public_keys: vec![],
                trusted_emergency_access_public_keys: vec![],
                upgrade_token_action: None,
            },
            sync.wrapped_account_cryptographic_state.clone(),
            sync,
        )
        .await;

        assert!(result.is_ok());
        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_key_management_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_rotate_user_keys_upgrade_token_action_skip_omits_token() {
        let (key_store, sync) = make_test_key_store_and_synced_data();
        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_rotate_user_keys()
                .once()
                .returning(|req| {
                    let req = req.expect("request body should be present");
                    assert!(
                        req.unlock_data.v2_upgrade_token.is_none(),
                        "upgrade_token_action Skip, should omit the v2_upgrade_token"
                    );
                    Ok(())
                });
        });

        let result = internal_rotate_user_keys(
            &key_store,
            &api_client,
            None,
            RotateUserKeysRequest {
                key_rotation_method: KeyRotationMethod::Password {
                    password: "test_password".to_string(),
                },
                trusted_organization_public_keys: vec![],
                trusted_emergency_access_public_keys: vec![],
                upgrade_token_action: Some(UpgradeTokenAction::Skip),
            },
            sync.wrapped_account_cryptographic_state.clone(),
            sync,
        )
        .await;

        assert!(result.is_ok());
        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_key_management_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_rotate_user_keys_upgrade_token_action_create_if_needed_includes_token() {
        let (key_store, sync) = make_test_key_store_and_synced_data();
        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_rotate_user_keys()
                .once()
                .returning(|req| {
                    let req = req.expect("request body should be present");
                    assert!(
                        req.unlock_data.v2_upgrade_token.is_some(),
                        "upgrade_token_action CreateIfNeeded, should include a v2_upgrade_token for V1 -> V2 rotations"
                    );
                    Ok(())
                });
        });

        let result = internal_rotate_user_keys(
            &key_store,
            &api_client,
            None,
            RotateUserKeysRequest {
                key_rotation_method: KeyRotationMethod::Password {
                    password: "test_password".to_string(),
                },
                trusted_organization_public_keys: vec![],
                trusted_emergency_access_public_keys: vec![],
                upgrade_token_action: Some(UpgradeTokenAction::CreateIfNeeded),
            },
            sync.wrapped_account_cryptographic_state.clone(),
            sync,
        )
        .await;

        assert!(result.is_ok());
        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_key_management_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_rotate_user_keys_old_attachments_returns_error() {
        let (key_store, mut sync) = make_test_key_store_and_synced_data();
        let enc_string = "2.STIyTrfDZN/JXNDN9zNEMw==|NDLum8BHZpPNYhJo9ggSkg==|UCsCLlBO3QzdPwvMAWs2VVwuE6xwOx/vxOooPObqnEw=";

        // Add a cipher with an old attachment (key is None)
        sync.ciphers = vec![Cipher {
            id: None,
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            r#type: CipherType::Login,
            login: None,
            identity: None,
            card: None,
            secure_note: None,
            ssh_key: None,
            bank_account: None,
            drivers_license: None,
            passport: None,
            favorite: false,
            reprompt: Default::default(),
            organization_use_totp: false,
            edit: false,
            permissions: None,
            view_password: false,
            name: enc_string.parse().unwrap(),
            revision_date: DateTime::from_str("2024-01-01T00:00:00Z").unwrap(),
            archived_date: None,
            creation_date: DateTime::from_str("2024-01-01T00:00:00Z").unwrap(),
            attachments: Some(vec![Attachment {
                id: None,
                url: None,
                size: None,
                size_name: None,
                file_name: None,
                key: None, // Old attachment - no per-attachment key
            }]),
            fields: None,
            key: None,
            notes: None,
            local_data: None,
            password_history: None,
            deleted_date: None,
            data: None,
        }];

        let api_client = ApiClient::new_mocked(|mock| {
            // Rotation API should never be called
            mock.accounts_key_management_api
                .expect_rotate_user_keys()
                .never();
        });

        let result = internal_rotate_user_keys(
            &key_store,
            &api_client,
            None,
            RotateUserKeysRequest {
                key_rotation_method: KeyRotationMethod::Password {
                    password: "test_password".to_string(),
                },
                trusted_organization_public_keys: vec![],
                trusted_emergency_access_public_keys: vec![],
                upgrade_token_action: None,
            },
            sync.wrapped_account_cryptographic_state.clone(),
            sync,
        )
        .await;

        assert!(matches!(result, Err(RotateUserKeysError::OldAttachments)));
        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_key_management_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_rotate_user_keys_key_connector_success() {
        let (key_store, sync) = make_test_key_store_and_synced_data();

        let key_connector_key = KeyConnectorKey::make();
        let key_connector_api_client = bitwarden_api_key_connector::apis::ApiClient::new_mocked(
            |mock| {
                let key_connector_key_clone = key_connector_key.clone();
                mock.user_keys_api
                    .expect_get_user_key()
                    .once()
                    .returning(move || {
                        let encoded: bitwarden_encoding::B64 =
                            key_connector_key_clone.clone().into();
                        Ok(
                            bitwarden_api_key_connector::models::user_key_response_model::UserKeyResponseModel {
                                key: encoded.to_string(),
                            },
                        )
                    });
            },
        );

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_rotate_user_keys()
                .once()
                .returning(|req| {
                    let req = req.expect("request body should be present");
                    assert!(
                        req.unlock_method_data
                            .key_connector_key_wrapped_user_key
                            .is_some(),
                        "key_connector_key_wrapped_user_key should be set for KC rotation"
                    );
                    assert!(
                        req.unlock_method_data.master_password_unlock_data.is_none(),
                        "master_password_unlock_data should be None for KC rotation"
                    );
                    Ok(())
                });
        });

        let result = internal_rotate_user_keys(
            &key_store,
            &api_client,
            Some(&key_connector_api_client),
            RotateUserKeysRequest {
                key_rotation_method: KeyRotationMethod::KeyConnector {
                    key_connector_url: "https://kc.example.com".to_string(),
                },
                trusted_organization_public_keys: vec![],
                trusted_emergency_access_public_keys: vec![],
                upgrade_token_action: None,
            },
            sync.wrapped_account_cryptographic_state.clone(),
            sync,
        )
        .await;

        assert!(result.is_ok());
        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_key_management_api.checkpoint();
        }
        if let bitwarden_api_key_connector::apis::ApiClient::Mock(mut mock) =
            key_connector_api_client
        {
            mock.user_keys_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_rotate_user_keys_key_connector_api_failure() {
        let (key_store, sync) = make_test_key_store_and_synced_data();

        let key_connector_api_client =
            bitwarden_api_key_connector::apis::ApiClient::new_mocked(|mock| {
                mock.user_keys_api
                    .expect_get_user_key()
                    .once()
                    .returning(move || {
                        Err(bitwarden_api_key_connector::apis::Error::ResponseError(
                            bitwarden_api_key_connector::apis::ResponseContent {
                                status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                                content: "Server Error".to_string(),
                            },
                        ))
                    });
            });

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_rotate_user_keys()
                .never();
        });

        let result = internal_rotate_user_keys(
            &key_store,
            &api_client,
            Some(&key_connector_api_client),
            RotateUserKeysRequest {
                key_rotation_method: KeyRotationMethod::KeyConnector {
                    key_connector_url: "https://kc.example.com".to_string(),
                },
                trusted_organization_public_keys: vec![],
                trusted_emergency_access_public_keys: vec![],
                upgrade_token_action: None,
            },
            sync.wrapped_account_cryptographic_state.clone(),
            sync,
        )
        .await;

        assert!(matches!(result, Err(RotateUserKeysError::KeyConnectorApi)));
        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_key_management_api.checkpoint();
        }
        if let bitwarden_api_key_connector::apis::ApiClient::Mock(mut mock) =
            key_connector_api_client
        {
            mock.user_keys_api.checkpoint();
        }
    }
}

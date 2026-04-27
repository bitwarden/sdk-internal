//! Client implementation for rotating user keys without a password change.
use bitwarden_api_api::models::RotateUserKeysRequestModel;
use bitwarden_core::key_management::KeySlotIds;
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
        crypto::rotate_account_cryptographic_state_to_wrapped_model,
        data::{check_for_old_attachments, reencrypt_data},
        rotation_context::make_rotation_context,
        sync::sync_current_account_data,
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
    /// Key connector user, key rotation without a password change.
    /// NOTE: This is not yet implemented and will return a
    /// RotateUserKeysError::UnimplementedKeyRotationMethod error if used.
    KeyConnector,
    /// TDE user, key rotation without a password change.
    /// NOTE: This is not yet implemented and will return a
    /// RotateUserKeysError::UnimplementedKeyRotationMethod error if used.
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

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl UserCryptoManagementClient {
    /// Rotates the user's encryption keys without a password change.
    pub async fn rotate_user_keys(
        &self,
        request: RotateUserKeysRequest,
    ) -> Result<(), RotateUserKeysError> {
        let api_client = &self.client.internal.get_api_configurations().api_client;
        let key_store = self.client.internal.get_key_store();
        internal_rotate_user_keys(key_store, api_client, request).await
    }
}

#[instrument(name = "rotate_user_keys", level = "info", skip_all, err)]
async fn internal_rotate_user_keys(
    key_store: &KeyStore<KeySlotIds>,
    api_client: &bitwarden_api_api::apis::ApiClient,
    request: RotateUserKeysRequest,
) -> Result<(), RotateUserKeysError> {
    // This guard should be removed once other key rotation methods are implemented.
    match &request.key_rotation_method {
        KeyRotationMethod::KeyConnector => {
            return Err(RotateUserKeysError::UnimplementedKeyRotationMethod);
        }
        KeyRotationMethod::Tde => {
            return Err(RotateUserKeysError::UnimplementedKeyRotationMethod);
        }
        KeyRotationMethod::Password { .. } => {}
    }

    let sync = sync_current_account_data(api_client)
        .await
        .map_err(|_| RotateUserKeysError::ApiError)?;

    // Fail early if any cipher has old attachments that would become irrecoverable
    check_for_old_attachments(&sync.ciphers)?;

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

        info!("Re-encrypting account primary unlock method for user key rotation");
        let unlock_method_input =
            PrimaryUnlockMethod::from_key_rotation_method(request.key_rotation_method, &sync)
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
    api_client
        .accounts_key_management_api()
        .rotate_user_keys(Some(post_request))
        .await
        .map_err(|_| RotateUserKeysError::ApiError)?;
    info!("Successfully rotated user account keys and data");
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{
        apis::ApiClient,
        models::{
            DeviceAuthRequestResponseModelListResponseModel,
            EmergencyAccessGranteeDetailsResponseModelListResponseModel, KdfType,
            MasterPasswordUnlockKdfResponseModel, MasterPasswordUnlockResponseModel,
            PrivateKeysResponseModel, ProfileOrganizationResponseModelListResponseModel,
            ProfileResponseModel, PublicKeyEncryptionKeyPairResponseModel, SyncResponseModel,
            UserDecryptionResponseModel, WebAuthnCredentialResponseModelListResponseModel,
        },
    };
    use bitwarden_core::key_management::{KeySlotIds, SymmetricKeySlotId};
    use bitwarden_crypto::{KeyStore, PublicKeyEncryptionAlgorithm, SymmetricKeyAlgorithm};

    use super::*;

    fn make_test_key_store_and_sync_response() -> (KeyStore<KeySlotIds>, SyncResponseModel) {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let wrapped_private_key = {
            let mut ctx = store.context_mut();
            let user_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            let _ = ctx.persist_symmetric_key(user_key, SymmetricKeySlotId::User);
            let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
            ctx.wrap_private_key(SymmetricKeySlotId::User, private_key)
                .unwrap()
        };

        let sync_response = SyncResponseModel {
            object: Some("sync".to_string()),
            profile: Some(Box::new(ProfileResponseModel {
                id: Some(uuid::Uuid::new_v4()),
                account_keys: Some(Box::new(PrivateKeysResponseModel {
                    object: None,
                    signature_key_pair: None,
                    public_key_encryption_key_pair: Box::new(
                        PublicKeyEncryptionKeyPairResponseModel {
                            object: None,
                            wrapped_private_key: Some(wrapped_private_key.to_string()),
                            public_key: None,
                            signed_public_key: None,
                        },
                    ),
                    security_state: None,
                })),
                ..ProfileResponseModel::default()
            })),
            folders: Some(vec![]),
            ciphers: Some(vec![]),
            sends: Some(vec![]),
            collections: None,
            domains: None,
            policies: None,
            user_decryption: Some(Box::new(UserDecryptionResponseModel {
                master_password_unlock: Some(Box::new(MasterPasswordUnlockResponseModel {
                    kdf: Box::new(MasterPasswordUnlockKdfResponseModel {
                        kdf_type: KdfType::PBKDF2_SHA256,
                        iterations: 600000,
                        memory: None,
                        parallelism: None,
                    }),
                    master_key_encrypted_user_key: None,
                    salt: Some("test_salt".to_string()),
                })),
                web_authn_prf_options: None,
                v2_upgrade_token: None,
            })),
        };

        (store, sync_response)
    }

    fn mock_empty_sync_calls(mock: &mut bitwarden_api_api::apis::ApiClientMock) {
        mock.organizations_api
            .expect_get_user()
            .once()
            .returning(|| {
                Ok(ProfileOrganizationResponseModelListResponseModel {
                    object: None,
                    data: Some(vec![]),
                    continuation_token: None,
                })
            });
        mock.emergency_access_api
            .expect_get_contacts()
            .once()
            .returning(|| {
                Ok(
                    EmergencyAccessGranteeDetailsResponseModelListResponseModel {
                        object: None,
                        data: Some(vec![]),
                        continuation_token: None,
                    },
                )
            });
        mock.devices_api.expect_get_all().once().returning(|| {
            Ok(DeviceAuthRequestResponseModelListResponseModel {
                object: None,
                data: Some(vec![]),
                continuation_token: None,
            })
        });
        mock.web_authn_api.expect_get().once().returning(|| {
            Ok(WebAuthnCredentialResponseModelListResponseModel {
                object: None,
                data: Some(vec![]),
                continuation_token: None,
            })
        });
    }

    #[tokio::test]
    async fn test_rotate_user_keys_key_connector_returns_unimplemented() {
        let key_store: KeyStore<KeySlotIds> = KeyStore::default();
        let api_client = ApiClient::new_mocked(|mock| {
            mock.sync_api.expect_get().never();
            mock.accounts_key_management_api
                .expect_rotate_user_keys()
                .never();
        });

        let result = internal_rotate_user_keys(
            &key_store,
            &api_client,
            RotateUserKeysRequest {
                key_rotation_method: KeyRotationMethod::KeyConnector,
                trusted_organization_public_keys: vec![],
                trusted_emergency_access_public_keys: vec![],
            },
        )
        .await;

        assert!(matches!(
            result,
            Err(RotateUserKeysError::UnimplementedKeyRotationMethod)
        ));
        if let ApiClient::Mock(mut mock) = api_client {
            mock.sync_api.checkpoint();
            mock.accounts_key_management_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_rotate_user_keys_tde_returns_unimplemented() {
        let key_store: KeyStore<KeySlotIds> = KeyStore::default();
        let api_client = ApiClient::new_mocked(|mock| {
            mock.sync_api.expect_get().never();
            mock.accounts_key_management_api
                .expect_rotate_user_keys()
                .never();
        });

        let result = internal_rotate_user_keys(
            &key_store,
            &api_client,
            RotateUserKeysRequest {
                key_rotation_method: KeyRotationMethod::Tde,
                trusted_organization_public_keys: vec![],
                trusted_emergency_access_public_keys: vec![],
            },
        )
        .await;

        assert!(matches!(
            result,
            Err(RotateUserKeysError::UnimplementedKeyRotationMethod)
        ));
        if let ApiClient::Mock(mut mock) = api_client {
            mock.sync_api.checkpoint();
            mock.accounts_key_management_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_rotate_user_keys_api_failure_returns_api_error() {
        let key_store: KeyStore<KeySlotIds> = KeyStore::default();
        let api_client = ApiClient::new_mocked(|mock| {
            mock.sync_api.expect_get().once().returning(|_| {
                Err(bitwarden_api_api::apis::Error::Serde(
                    serde_json::Error::io(std::io::Error::other("network error")),
                ))
            });
            mock.accounts_key_management_api
                .expect_rotate_user_keys()
                .never();
        });

        let result = internal_rotate_user_keys(
            &key_store,
            &api_client,
            RotateUserKeysRequest {
                key_rotation_method: KeyRotationMethod::Password {
                    password: "test".to_string(),
                },
                trusted_organization_public_keys: vec![],
                trusted_emergency_access_public_keys: vec![],
            },
        )
        .await;

        assert!(matches!(result, Err(RotateUserKeysError::ApiError)));
        if let ApiClient::Mock(mut mock) = api_client {
            mock.sync_api.checkpoint();
            mock.accounts_key_management_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_rotate_user_keys_master_password_success() {
        let (key_store, sync_response) = make_test_key_store_and_sync_response();
        let api_client = ApiClient::new_mocked(|mock| {
            mock.sync_api
                .expect_get()
                .once()
                .returning(move |_| Ok(sync_response.clone()));
            mock_empty_sync_calls(mock);
            mock.accounts_key_management_api
                .expect_rotate_user_keys()
                .once()
                .returning(|_| Ok(()));
        });

        let result = internal_rotate_user_keys(
            &key_store,
            &api_client,
            RotateUserKeysRequest {
                key_rotation_method: KeyRotationMethod::Password {
                    password: "test_password".to_string(),
                },
                trusted_organization_public_keys: vec![],
                trusted_emergency_access_public_keys: vec![],
            },
        )
        .await;

        assert!(result.is_ok());
        if let ApiClient::Mock(mut mock) = api_client {
            mock.sync_api.checkpoint();
            mock.organizations_api.checkpoint();
            mock.emergency_access_api.checkpoint();
            mock.devices_api.checkpoint();
            mock.web_authn_api.checkpoint();
            mock.accounts_key_management_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_rotate_user_keys_post_api_failure_returns_api_error() {
        let (key_store, sync_response) = make_test_key_store_and_sync_response();
        let api_client = ApiClient::new_mocked(|mock| {
            mock.sync_api
                .expect_get()
                .once()
                .returning(move |_| Ok(sync_response.clone()));
            mock_empty_sync_calls(mock);
            mock.accounts_key_management_api
                .expect_rotate_user_keys()
                .once()
                .returning(|_| {
                    Err(bitwarden_api_api::apis::Error::Serde(
                        serde_json::Error::io(std::io::Error::other("API error")),
                    ))
                });
        });

        let result = internal_rotate_user_keys(
            &key_store,
            &api_client,
            RotateUserKeysRequest {
                key_rotation_method: KeyRotationMethod::Password {
                    password: "test_password".to_string(),
                },
                trusted_organization_public_keys: vec![],
                trusted_emergency_access_public_keys: vec![],
            },
        )
        .await;

        assert!(matches!(result, Err(RotateUserKeysError::ApiError)));
        if let ApiClient::Mock(mut mock) = api_client {
            mock.sync_api.checkpoint();
            mock.organizations_api.checkpoint();
            mock.emergency_access_api.checkpoint();
            mock.devices_api.checkpoint();
            mock.web_authn_api.checkpoint();
            mock.accounts_key_management_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_rotate_user_keys_old_attachments_returns_error() {
        use bitwarden_api_api::models::{
            AttachmentResponseModel, CipherDetailsResponseModel, CipherType,
        };

        let (key_store, mut sync_response) = make_test_key_store_and_sync_response();
        let enc_string = "2.STIyTrfDZN/JXNDN9zNEMw==|NDLum8BHZpPNYhJo9ggSkg==|UCsCLlBO3QzdPwvMAWs2VVwuE6xwOx/vxOooPObqnEw=";

        // Add a cipher with an old attachment (key is None)
        sync_response.ciphers = Some(vec![CipherDetailsResponseModel {
            id: Some(uuid::Uuid::new_v4()),
            organization_id: None,
            r#type: Some(CipherType::Login),
            name: Some(enc_string.to_string()),
            revision_date: Some("2024-01-01T00:00:00Z".to_string()),
            creation_date: Some("2024-01-01T00:00:00Z".to_string()),
            attachments: Some(vec![AttachmentResponseModel {
                id: Some("att1".to_string()),
                file_name: Some(enc_string.to_string()),
                key: None, // Old attachment - no per-attachment key
                ..AttachmentResponseModel::new()
            }]),
            ..CipherDetailsResponseModel::new()
        }]);

        let api_client = ApiClient::new_mocked(|mock| {
            mock.sync_api
                .expect_get()
                .once()
                .returning(move |_| Ok(sync_response.clone()));
            mock_empty_sync_calls(mock);
            // Rotation API should never be called
            mock.accounts_key_management_api
                .expect_rotate_user_keys()
                .never();
        });

        let result = internal_rotate_user_keys(
            &key_store,
            &api_client,
            RotateUserKeysRequest {
                key_rotation_method: KeyRotationMethod::Password {
                    password: "test_password".to_string(),
                },
                trusted_organization_public_keys: vec![],
                trusted_emergency_access_public_keys: vec![],
            },
        )
        .await;

        assert!(matches!(result, Err(RotateUserKeysError::OldAttachments)));
        if let ApiClient::Mock(mut mock) = api_client {
            mock.sync_api.checkpoint();
            mock.organizations_api.checkpoint();
            mock.emergency_access_api.checkpoint();
            mock.devices_api.checkpoint();
            mock.web_authn_api.checkpoint();
            mock.accounts_key_management_api.checkpoint();
        }
    }
}

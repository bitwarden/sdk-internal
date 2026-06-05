//! Client implementation for rotating user keys without a password change.
use bitwarden_api_api::models::RotateUserKeysRequestModel;
use bitwarden_core::key_management::{
    KeySlotIds, V2UpgradeToken, account_cryptographic_state::WrappedAccountCryptographicState,
};
use bitwarden_crypto::{KeyConnectorKey, KeyStore, PublicKey, SymmetricCryptoKey};
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
        crypto::{
            account_cryptographic_state_to_wrapped_model, rotate_account_cryptographic_state,
        },
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
    Tde,
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum UpgradeTokenAction {
    /// Skip creating and sending an upgrade token to the server.
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
    pub upgrade_token_action: UpgradeTokenAction,
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
            &self.client.km_state_bridge(),
            key_connector_api_client.as_ref(),
            request,
            wrapped_account_cryptographic_state,
            sync,
        )
        .await
    }
}

/// Data that needs to be written to local state after the key rotation
/// was successfully posted to the server
struct StateUpdate {
    user_key: SymmetricCryptoKey,
    account_cryptographic_state: WrappedAccountCryptographicState,
    upgrade_token: Option<V2UpgradeToken>,
}

#[instrument(name = "rotate_user_keys", level = "info", skip_all, err)]
async fn internal_rotate_user_keys(
    key_store: &KeyStore<KeySlotIds>,
    api_client: &bitwarden_api_api::apis::ApiClient,
    state_bridge: &bitwarden_core::key_management::state_bridge::StateBridgeClient,
    key_connector_api_client: Option<&bitwarden_api_key_connector::apis::ApiClient>,
    request: RotateUserKeysRequest,
    wrapped_account_cryptographic_state: WrappedAccountCryptographicState,
    sync: SyncedAccountData,
) -> Result<(), RotateUserKeysError> {
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
    let (post_request, state_bridge_update) = {
        let mut ctx = key_store.context_mut();

        let rotation_context = make_rotation_context(
            &sync,
            request.trusted_organization_public_keys.as_slice(),
            request.trusted_emergency_access_public_keys.as_slice(),
            &mut ctx,
        )?;

        info!("Rotating account cryptographic state for user key rotation");
        let wrapped_account_cryptographic_state = rotate_account_cryptographic_state(
            &wrapped_account_cryptographic_state,
            &rotation_context.current_user_key_id,
            &rotation_context.new_user_key_id,
            &mut ctx,
        )
        .map_err(|_| RotateUserKeysError::Crypto)?;
        let wrapped_account_cryptographic_state_request_model =
            account_cryptographic_state_to_wrapped_model(
                &wrapped_account_cryptographic_state,
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
            request.upgrade_token_action,
            &mut ctx,
        )
        .map_err(|_| RotateUserKeysError::Crypto)?;

        (
            RotateUserKeysRequestModel {
                wrapped_account_cryptographic_state: Box::new(
                    wrapped_account_cryptographic_state_request_model,
                ),
                account_data: Box::new(account_data_model),
                unlock_data: Box::new(common_unlock_data.clone()),
                unlock_method_data: Box::new(unlock_method_data),
            },
            StateUpdate {
                #[allow(deprecated)]
                user_key: ctx
                    .dangerous_get_symmetric_key(rotation_context.new_user_key_id)
                    .map_err(|_| RotateUserKeysError::Crypto)?
                    .to_owned(),
                account_cryptographic_state: wrapped_account_cryptographic_state,
                upgrade_token: common_unlock_data
                    .v2_upgrade_token
                    .clone()
                    .map(|t| (*t).try_into())
                    .transpose()
                    .map_err(|_| RotateUserKeysError::Crypto)?,
            },
        )
    };

    info!("Posting rotated user account keys and data to server");
    api_client
        .accounts_key_management_api()
        .rotate_user_keys(Some(post_request))
        .await
        .map_err(|_| RotateUserKeysError::Api)?;
    info!("Successfully rotated user account keys and data");

    if let Some(upgrade_token) = state_bridge_update.upgrade_token.as_ref() {
        info!("Writing new cryptographic data to state");
        state_bridge
            .set_account_cryptographic_state(&state_bridge_update.account_cryptographic_state)
            .await;
        state_bridge.set_v2_upgrade_token(upgrade_token).await;
        state_bridge
            .set_user_key(&state_bridge_update.user_key)
            .await;
        // Important: A full sync MUST be triggered after the key rotation to make sure all unlock
        // methods are accurate
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitwarden_api_api::{apis::ApiClient, models::UnlockMethod};
    use bitwarden_core::{
        Client,
        key_management::{
            KeySlotIds, PrivateKeySlotId, SymmetricKeySlotId,
            account_cryptographic_state::WrappedAccountCryptographicState,
            state_bridge::{StateBridgeClient, test_support::InMemoryStateBridge},
        },
    };
    use bitwarden_crypto::{
        Decryptable, EncString, Kdf, KeyStore, PublicKeyEncryptionAlgorithm, SymmetricKeyAlgorithm,
        UnsignedSharedKey,
    };
    use bitwarden_vault::{Attachment, Cipher, CipherType};
    use chrono::DateTime;

    use super::*;
    use crate::key_rotation::partial_rotateable_keyset::PartialRotateableKeyset;

    fn make_state_bridge() -> StateBridgeClient {
        let client = Client::new(None);
        let bridge = client.km_state_bridge();
        bridge.register_bridge(Box::new(InMemoryStateBridge::default()));
        bridge
    }

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

    fn make_test_key_store_and_synced_data_with_trusted_devices()
    -> (KeyStore<KeySlotIds>, SyncedAccountData, Vec<u8>) {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let (trusted_device_keyset, wrapped_private_key, public_key) = {
            let mut ctx = store.context_mut();
            let user_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
            let _ = ctx.persist_symmetric_key(user_key, SymmetricKeySlotId::User);
            let (trusted_device_keyset, device_private_key) =
                PartialRotateableKeyset::make_test_keyset(SymmetricKeySlotId::User, &mut ctx);
            let _ = ctx.persist_private_key(device_private_key, PrivateKeySlotId::UserPrivateKey);
            let wrapped_private_key = ctx
                .wrap_private_key(SymmetricKeySlotId::User, PrivateKeySlotId::UserPrivateKey)
                .unwrap();
            (
                trusted_device_keyset,
                wrapped_private_key,
                ctx.get_public_key(PrivateKeySlotId::UserPrivateKey)
                    .expect("Retrieving the public key should work."),
            )
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
            trusted_devices: vec![trusted_device_keyset],
            passkeys: vec![],
            kdf_and_salt: Some((
                Kdf::PBKDF2 {
                    iterations: std::num::NonZeroU32::new(600000).unwrap(),
                },
                "test_salt".to_string(),
            )),
        };

        (
            store,
            sync,
            public_key
                .to_der()
                .expect("Generating DER serialization should work")
                .to_vec(),
        )
    }

    #[tokio::test]
    async fn test_rotate_user_keys_tde_success_rotates_common_unlock_data() {
        let (key_store, sync, public_key_der) =
            make_test_key_store_and_synced_data_with_trusted_devices();
        let key_store_clone = key_store.clone();

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_rotate_user_keys()
                .once()
                .returning(move |req| {
                    let req = req.expect("request body should be present");
                    assert_eq!(req.unlock_method_data.unlock_method, UnlockMethod::Tde);
                    assert!(req.unlock_method_data.master_password_unlock_data.is_none());
                    assert!(
                        req.unlock_method_data
                            .key_connector_key_wrapped_user_key
                            .is_none()
                    );

                    let device_unlock_data = req
                        .unlock_data
                        .device_key_unlock_data
                        .expect("device unlock data should be present");
                    assert_eq!(device_unlock_data.len(), 1);
                    let rotated_device = &device_unlock_data[0];

                    let encrypted_user_key: UnsignedSharedKey = rotated_device
                        .encrypted_user_key
                        .parse()
                        .expect("encrypted user key should parse");
                    let encrypted_public_key: EncString = rotated_device
                        .encrypted_public_key
                        .parse()
                        .expect("encrypted public key should parse");
                    let mut ctx = key_store_clone.context_mut();
                    let rotated_user_key_id = encrypted_user_key
                        .decapsulate(PrivateKeySlotId::UserPrivateKey, &mut ctx)
                        .expect("rotated device user key should decapsulate");
                    let decrypted_public_key: Vec<u8> = encrypted_public_key
                        .decrypt(&mut ctx, rotated_user_key_id)
                        .expect("rotated device public key should decrypt");
                    assert_eq!(decrypted_public_key, public_key_der);
                    Ok(())
                });
        });

        let state_bridge = make_state_bridge();
        let result = internal_rotate_user_keys(
            &key_store,
            &api_client,
            &state_bridge,
            None,
            RotateUserKeysRequest {
                key_rotation_method: KeyRotationMethod::Tde,
                trusted_organization_public_keys: vec![],
                trusted_emergency_access_public_keys: vec![],
                upgrade_token_action: UpgradeTokenAction::Skip,
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
    async fn test_rotate_user_keys_master_password_success() {
        let (key_store, sync) = make_test_key_store_and_synced_data();
        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_rotate_user_keys()
                .once()
                .returning(|_| Ok(()));
        });

        let state_bridge = make_state_bridge();
        let result = internal_rotate_user_keys(
            &key_store,
            &api_client,
            &state_bridge,
            None,
            RotateUserKeysRequest {
                key_rotation_method: KeyRotationMethod::Password {
                    password: "test_password".to_string(),
                },
                trusted_organization_public_keys: vec![],
                trusted_emergency_access_public_keys: vec![],
                upgrade_token_action: UpgradeTokenAction::Skip,
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

        let state_bridge = make_state_bridge();
        let result = internal_rotate_user_keys(
            &key_store,
            &api_client,
            &state_bridge,
            None,
            RotateUserKeysRequest {
                key_rotation_method: KeyRotationMethod::Password {
                    password: "test_password".to_string(),
                },
                trusted_organization_public_keys: vec![],
                trusted_emergency_access_public_keys: vec![],
                upgrade_token_action: UpgradeTokenAction::Skip,
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

        let state_bridge = make_state_bridge();
        let result = internal_rotate_user_keys(
            &key_store,
            &api_client,
            &state_bridge,
            None,
            RotateUserKeysRequest {
                key_rotation_method: KeyRotationMethod::Password {
                    password: "test_password".to_string(),
                },
                trusted_organization_public_keys: vec![],
                trusted_emergency_access_public_keys: vec![],
                upgrade_token_action: UpgradeTokenAction::Skip,
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

        let state_bridge = make_state_bridge();
        let result = internal_rotate_user_keys(
            &key_store,
            &api_client,
            &state_bridge,
            None,
            RotateUserKeysRequest {
                key_rotation_method: KeyRotationMethod::Password {
                    password: "test_password".to_string(),
                },
                trusted_organization_public_keys: vec![],
                trusted_emergency_access_public_keys: vec![],
                upgrade_token_action: UpgradeTokenAction::CreateIfNeeded,
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
    async fn test_rotate_user_keys_writes_state_when_upgrade_token_present() {
        let (key_store, sync) = make_test_key_store_and_synced_data();
        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_rotate_user_keys()
                .once()
                .returning(|_| Ok(()));
        });

        let state_bridge = make_state_bridge();
        assert!(state_bridge.get_v2_upgrade_token().await.is_none());
        assert!(
            state_bridge
                .get_account_cryptographic_state()
                .await
                .is_none()
        );
        assert!(state_bridge.get_user_key().await.is_none());

        let result = internal_rotate_user_keys(
            &key_store,
            &api_client,
            &state_bridge,
            None,
            RotateUserKeysRequest {
                key_rotation_method: KeyRotationMethod::Password {
                    password: "test_password".to_string(),
                },
                trusted_organization_public_keys: vec![],
                trusted_emergency_access_public_keys: vec![],
                upgrade_token_action: UpgradeTokenAction::CreateIfNeeded,
            },
            sync.wrapped_account_cryptographic_state.clone(),
            sync,
        )
        .await;

        assert!(result.is_ok());
        assert!(
            state_bridge.get_v2_upgrade_token().await.is_some(),
            "state bridge should hold the v2 upgrade token after V1 -> V2 rotation"
        );
        assert!(
            state_bridge
                .get_account_cryptographic_state()
                .await
                .is_some(),
            "state bridge should hold the rotated account cryptographic state"
        );
        assert!(
            state_bridge.get_user_key().await.is_some(),
            "state bridge should hold the rotated user key"
        );
        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_key_management_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_rotate_user_keys_skips_state_writes_when_no_upgrade_token() {
        let (key_store, sync) = make_test_key_store_and_synced_data();
        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_rotate_user_keys()
                .once()
                .returning(|_| Ok(()));
        });

        let state_bridge = make_state_bridge();
        let result = internal_rotate_user_keys(
            &key_store,
            &api_client,
            &state_bridge,
            None,
            RotateUserKeysRequest {
                key_rotation_method: KeyRotationMethod::Password {
                    password: "test_password".to_string(),
                },
                trusted_organization_public_keys: vec![],
                trusted_emergency_access_public_keys: vec![],
                upgrade_token_action: UpgradeTokenAction::Skip,
            },
            sync.wrapped_account_cryptographic_state.clone(),
            sync,
        )
        .await;

        assert!(result.is_ok());
        assert!(
            state_bridge.get_v2_upgrade_token().await.is_none(),
            "without an upgrade token, the state bridge must not be written"
        );
        assert!(
            state_bridge
                .get_account_cryptographic_state()
                .await
                .is_none()
        );
        assert!(state_bridge.get_user_key().await.is_none());
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
            name: Some(enc_string.parse().unwrap()),
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

        let state_bridge = make_state_bridge();
        let result = internal_rotate_user_keys(
            &key_store,
            &api_client,
            &state_bridge,
            None,
            RotateUserKeysRequest {
                key_rotation_method: KeyRotationMethod::Password {
                    password: "test_password".to_string(),
                },
                trusted_organization_public_keys: vec![],
                trusted_emergency_access_public_keys: vec![],
                upgrade_token_action: UpgradeTokenAction::Skip,
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

        let state_bridge = make_state_bridge();
        let result = internal_rotate_user_keys(
            &key_store,
            &api_client,
            &state_bridge,
            Some(&key_connector_api_client),
            RotateUserKeysRequest {
                key_rotation_method: KeyRotationMethod::KeyConnector {
                    key_connector_url: "https://kc.example.com".to_string(),
                },
                trusted_organization_public_keys: vec![],
                trusted_emergency_access_public_keys: vec![],
                upgrade_token_action: UpgradeTokenAction::Skip,
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

        let state_bridge = make_state_bridge();
        let result = internal_rotate_user_keys(
            &key_store,
            &api_client,
            &state_bridge,
            Some(&key_connector_api_client),
            RotateUserKeysRequest {
                key_rotation_method: KeyRotationMethod::KeyConnector {
                    key_connector_url: "https://kc.example.com".to_string(),
                },
                trusted_organization_public_keys: vec![],
                trusted_emergency_access_public_keys: vec![],
                upgrade_token_action: UpgradeTokenAction::Skip,
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

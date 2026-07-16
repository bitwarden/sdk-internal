//! Functionality for syncing the latest account data from the server
use bitwarden_api_api::apis::ApiClient;
use bitwarden_core::key_management::account_cryptographic_state::WrappedAccountCryptographicState;
use bitwarden_crypto::Kdf;
use bitwarden_error::bitwarden_error;
use bitwarden_vault::{Cipher, Folder};
use thiserror::Error;
use tracing::{debug, debug_span, info};

use crate::key_rotation::{
    partial_rotateable_keyset::PartialRotateableKeyset,
    unlock::{V1EmergencyAccessMembership, V1OrganizationMembership},
};

trait DebugMapErr<T, E: std::fmt::Debug> {
    /// Logs the error using `tracing::debug` and maps it to a new error type
    fn debug_map_err<E2>(self, target: E2) -> Result<T, E2>;
}

impl<T, E: std::fmt::Debug> DebugMapErr<T, E> for Result<T, E> {
    fn debug_map_err<E2>(self, target: E2) -> Result<T, E2> {
        self.map_err(|e| {
            debug!(error = ?e);
            target
        })
    }
}

pub(super) struct SyncedAccountData {
    pub(super) wrapped_account_cryptographic_state: WrappedAccountCryptographicState,
    pub(super) folders: Vec<Folder>,
    pub(super) ciphers: Vec<Cipher>,
    pub(super) sends: Vec<bitwarden_send::Send>,
    pub(super) emergency_access_memberships: Vec<V1EmergencyAccessMembership>,
    pub(super) organization_memberships: Vec<V1OrganizationMembership>,
    pub(super) trusted_devices: Vec<PartialRotateableKeyset>,
    pub(super) passkeys: Vec<PartialRotateableKeyset>,
    pub(super) kdf_and_salt: Option<(Kdf, String)>,
}

#[derive(Debug, Error)]
#[bitwarden_error(flat)]
pub(super) enum SyncError {
    #[error("Network error during sync")]
    Network,
    #[error("Failed to parse sync data")]
    Data,
}

/// The account keys data needed for key rotation, fetched from the key rotation data endpoint.
pub(super) struct KeyRotationData {
    pub(super) organization_memberships: Vec<V1OrganizationMembership>,
    pub(super) emergency_access_memberships: Vec<V1EmergencyAccessMembership>,
    pub(super) trusted_devices: Vec<PartialRotateableKeyset>,
    pub(super) passkeys: Vec<PartialRotateableKeyset>,
}

/// Download the key rotation data from the server. This is the public keys for the
/// password reset enrolled organizations and emergency-access grantees, and the encrypted keysets
/// for the trusted devices and PRF-enabled passkeys. The server filters these to only the entries
/// that participate in key rotation, so no client-side filtering is required.
pub(super) async fn get_key_rotation_data(
    api_client: &ApiClient,
) -> Result<KeyRotationData, SyncError> {
    let data = api_client
        .accounts_key_management_api()
        .get_key_rotation_data()
        .await
        .debug_map_err(SyncError::Network)?;

    let organization_memberships = data
        .organization_password_reset_key_data
        .ok_or(SyncError::Data)?
        .into_iter()
        .map(|response| {
            let _span = debug_span!("deserializing_organization_membership", organization_id = ?response.organization_id).entered();
            V1OrganizationMembership::try_from(response).debug_map_err(SyncError::Data)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let emergency_access_memberships = data
        .emergency_access_key_data
        .ok_or(SyncError::Data)?
        .into_iter()
        .map(|response| {
            let _span = debug_span!("deserializing_emergency_access_membership", emergency_access_id = ?response.id).entered();
            V1EmergencyAccessMembership::try_from(response).debug_map_err(SyncError::Data)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let trusted_devices = data
        .trusted_device_key_data
        .ok_or(SyncError::Data)?
        .into_iter()
        .map(|response| {
            let _span =
                debug_span!("deserializing_trusted_device", device_id = ?response.id).entered();
            PartialRotateableKeyset::try_from(response).debug_map_err(SyncError::Data)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let passkeys = data
        .passkey_key_data
        .ok_or(SyncError::Data)?
        .into_iter()
        .map(|response| {
            let _span = debug_span!("deserializing_passkey", passkey_id = ?response.id).entered();
            PartialRotateableKeyset::try_from(response).debug_map_err(SyncError::Data)
        })
        .collect::<Result<Vec<_>, _>>()?;

    info!(
        "Downloaded key rotation data: {} organizations, {} emergency access, {} devices, {} passkeys",
        organization_memberships.len(),
        emergency_access_memberships.len(),
        trusted_devices.len(),
        passkeys.len(),
    );

    Ok(KeyRotationData {
        organization_memberships,
        emergency_access_memberships,
        trusted_devices,
        passkeys,
    })
}

fn parse_ciphers(
    ciphers: Option<Vec<bitwarden_api_api::models::CipherDetailsResponseModel>>,
) -> Result<Vec<Cipher>, SyncError> {
    let ciphers = ciphers
        .ok_or(SyncError::Data)?
        .into_iter()
        .filter(|c| c.organization_id.is_none())
        .map(|c| {
            let _span = debug_span!("deserializing_cipher", cipher_id = ?c.id).entered();
            Cipher::try_from(c).debug_map_err(SyncError::Data)
        })
        .collect::<Result<Vec<_>, _>>()?;
    info!("Deserialized {} ciphers", ciphers.len());
    Ok(ciphers)
}

fn parse_folders(
    folders: Option<Vec<bitwarden_api_api::models::FolderResponseModel>>,
) -> Result<Vec<Folder>, SyncError> {
    let folders = folders
        .ok_or(SyncError::Data)?
        .into_iter()
        .map(|f| {
            let _span = debug_span!("deserializing_folder", folder_id = ?f.id).entered();
            Folder::try_from(f).debug_map_err(SyncError::Data)
        })
        .collect::<Result<Vec<_>, _>>()?;
    info!("Deserialized {} folders", folders.len());
    Ok(folders)
}

fn parse_sends(
    sends: Option<Vec<bitwarden_api_api::models::SendResponseModel>>,
) -> Result<Vec<bitwarden_send::Send>, SyncError> {
    let sends = sends
        .ok_or(SyncError::Data)?
        .into_iter()
        .map(|s| {
            let _span = debug_span!("deserializing_send", send_id = ?s.id).entered();
            bitwarden_send::Send::try_from(s).debug_map_err(SyncError::Data)
        })
        .collect::<Result<Vec<_>, _>>()?;
    info!("Deserialized {} sends", sends.len());
    Ok(sends)
}

fn from_kdf(
    kdf: &bitwarden_api_api::models::MasterPasswordUnlockKdfResponseModel,
) -> Result<Kdf, ()> {
    Ok(match kdf.kdf_type {
        bitwarden_api_api::models::KdfType::PBKDF2_SHA256 => Kdf::PBKDF2 {
            iterations: std::num::NonZeroU32::new(kdf.iterations.try_into().debug_map_err(())?)
                .ok_or(())?,
        },
        bitwarden_api_api::models::KdfType::Argon2id => {
            let memory = kdf.memory.ok_or(())?;
            let parallelism = kdf.parallelism.ok_or(())?;
            Kdf::Argon2id {
                iterations: std::num::NonZeroU32::new(kdf.iterations.try_into().debug_map_err(())?)
                    .ok_or(())?,
                memory: std::num::NonZeroU32::new(memory.try_into().debug_map_err(())?).ok_or(())?,
                parallelism: std::num::NonZeroU32::new(parallelism.try_into().debug_map_err(())?)
                    .ok_or(())?,
            }
        }
        bitwarden_api_api::models::KdfType::__Unknown(_) => return Err(()),
    })
}

/// Parses the user's KDF and salt from the sync response. If the user is not a master-password
/// user, returns Ok(None)
fn parse_kdf_and_salt(
    user_decryption: &Option<Box<bitwarden_api_api::models::UserDecryptionResponseModel>>,
) -> Result<Option<(Kdf, String)>, SyncError> {
    let user_decryption_options = user_decryption.as_ref().ok_or(SyncError::Data)?;
    if let Some(master_password_unlock) = &user_decryption_options.master_password_unlock {
        let kdf = from_kdf(&master_password_unlock.clone().kdf).debug_map_err(SyncError::Data)?;
        let salt = master_password_unlock.clone().salt.ok_or(SyncError::Data)?;
        debug!("Parsed password KDF and salt from sync response");
        Ok(Some((kdf, salt)))
    } else {
        debug!(
            "User does not have master password decryption options, skipping KDF and salt parsing"
        );
        Ok(None)
    }
}

pub(super) async fn sync_current_account_data(
    api_client: &ApiClient,
) -> Result<SyncedAccountData, SyncError> {
    info!("Syncing latest vault state from server for key rotation");
    let sync = api_client
        .sync_api()
        .get(Some(true))
        .await
        .debug_map_err(SyncError::Network)?;

    let profile = sync.profile.as_ref().ok_or(SyncError::Data)?;
    // This is optional for master-password-users!
    let kdf_and_salt = parse_kdf_and_salt(&sync.user_decryption)?;
    let account_cryptographic_state = profile.account_keys.to_owned().ok_or(SyncError::Data)?;
    let ciphers = parse_ciphers(sync.ciphers)?;
    let folders = parse_folders(sync.folders)?;
    let sends = parse_sends(sync.sends)?;
    let wrapped_account_cryptographic_state =
        WrappedAccountCryptographicState::try_from(account_cryptographic_state.as_ref())
            .debug_map_err(SyncError::Data)?;

    // Get the key rotation data (organizations, emergency access, devices, passkeys) in a single
    // request. The server filters these down to the entries that participate in key rotation.
    info!("Syncing key rotation data (organizations, emergency access, devices, passkeys)");
    let key_rotation_data = get_key_rotation_data(api_client).await?;

    Ok(SyncedAccountData {
        wrapped_account_cryptographic_state,
        folders,
        ciphers,
        sends,
        emergency_access_memberships: key_rotation_data.emergency_access_memberships,
        organization_memberships: key_rotation_data.organization_memberships,
        trusted_devices: key_rotation_data.trusted_devices,
        passkeys: key_rotation_data.passkeys,
        kdf_and_salt,
    })
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{
        apis::ApiClient,
        models::{
            EmergencyAccessKeyDataResponseModel, FolderResponseModel, KdfType,
            KeyRotationDataResponseModel, MasterPasswordUnlockKdfResponseModel,
            MasterPasswordUnlockResponseModel, OrganizationPasswordResetKeyDataResponseModel,
            PasskeyKeyDataResponseModel, PrivateKeysResponseModel, ProfileResponseModel,
            PublicKeyEncryptionKeyPairResponseModel, SendResponseModel, SendType,
            SyncResponseModel, TrustedDeviceKeyDataResponseModel, UserDecryptionResponseModel,
        },
    };
    use bitwarden_crypto::{PublicKey, SpkiPublicKeyBytes};
    use bitwarden_encoding::B64;
    use bitwarden_send::SendId;
    use bitwarden_vault::{CipherId, FolderId};

    use super::*;

    const TEST_ENC_STRING: &str = "2.STIyTrfDZN/JXNDN9zNEMw==|NDLum8BHZpPNYhJo9ggSkg==|UCsCLlBO3QzdPwvMAWs2VVwuE6xwOx/vxOooPObqnEw=";
    const KEY_ENC_STRING: &str = "2.KLv/j0V4Ebs0dwyPdtt4vw==|Nczvv+DTkeP466cP/wMDnGK6W9zEIg5iHLhcuQG6s+M=|SZGsfuIAIaGZ7/kzygaVUau3LeOvJUlolENBOU+LX7g=";
    const TEST_UNSIGNED_SHARED_KEY: &str = "4.AAAAAAAAAAAAAAAAAAAAAA==";

    const TEST_RSA_PUBLIC_KEY_BYTES: &[u8] = &[
        48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0,
        48, 130, 1, 10, 2, 130, 1, 1, 0, 173, 4, 54, 63, 125, 12, 254, 38, 115, 34, 95, 164, 148,
        115, 86, 140, 129, 74, 19, 70, 212, 212, 130, 163, 105, 249, 101, 120, 154, 46, 194, 250,
        229, 242, 156, 67, 109, 179, 187, 134, 59, 235, 60, 107, 144, 163, 35, 22, 109, 230, 134,
        243, 44, 243, 79, 84, 76, 11, 64, 56, 236, 167, 98, 26, 30, 213, 143, 105, 52, 92, 129, 92,
        88, 22, 115, 135, 63, 215, 79, 8, 11, 183, 124, 10, 73, 231, 170, 110, 210, 178, 22, 100,
        76, 75, 118, 202, 252, 204, 67, 204, 152, 6, 244, 208, 161, 146, 103, 225, 233, 239, 88,
        195, 88, 150, 230, 111, 62, 142, 12, 157, 184, 155, 34, 84, 237, 111, 11, 97, 56, 152, 130,
        14, 72, 123, 140, 47, 137, 5, 97, 166, 4, 147, 111, 23, 65, 78, 63, 208, 198, 50, 161, 39,
        80, 143, 100, 194, 37, 252, 194, 53, 207, 166, 168, 250, 165, 121, 9, 207, 90, 36, 213,
        211, 84, 255, 14, 205, 114, 135, 217, 137, 105, 232, 58, 169, 222, 10, 13, 138, 203, 16,
        12, 122, 72, 227, 95, 160, 111, 54, 200, 198, 143, 156, 15, 143, 196, 50, 150, 204, 144,
        255, 162, 248, 50, 28, 47, 66, 9, 83, 158, 67, 9, 50, 147, 174, 147, 200, 199, 238, 190,
        248, 60, 114, 218, 32, 209, 120, 218, 17, 234, 14, 128, 192, 166, 33, 60, 73, 227, 108,
        201, 41, 160, 81, 133, 171, 205, 221, 2, 3, 1, 0, 1,
    ];

    fn test_public_key_b64() -> String {
        B64::from(TEST_RSA_PUBLIC_KEY_BYTES.to_vec()).to_string()
    }

    fn create_test_folder(id: uuid::Uuid) -> FolderResponseModel {
        FolderResponseModel {
            object: Some("folder".to_string()),
            id: Some(id),
            name: Some(TEST_ENC_STRING.to_string()),
            revision_date: Some("2024-01-01T00:00:00Z".to_string()),
        }
    }

    fn create_test_cipher(id: uuid::Uuid) -> bitwarden_api_api::models::CipherDetailsResponseModel {
        bitwarden_api_api::models::CipherDetailsResponseModel {
            object: Some("cipher".to_string()),
            id: Some(id),
            organization_id: None,
            r#type: Some(bitwarden_api_api::models::CipherType::Login),
            data: None,
            partial_data: None,
            name: Some(TEST_ENC_STRING.to_string()),
            notes: None,
            login: None,
            card: None,
            identity: None,
            secure_note: None,
            ssh_key: None,
            bank_account: None,
            drivers_license: None,
            passport: None,
            fields: None,
            password_history: None,
            attachments: None,
            organization_use_totp: Some(false),
            revision_date: Some("2024-01-01T00:00:00Z".to_string()),
            creation_date: Some("2024-01-01T00:00:00Z".to_string()),
            deleted_date: None,
            reprompt: Some(bitwarden_api_api::models::CipherRepromptType::None),
            key: None,
            archived_date: None,
            folder_id: None,
            favorite: Some(false),
            edit: Some(true),
            view_password: Some(true),
            permissions: None,
            collection_ids: None,
        }
    }

    fn create_test_send(id: uuid::Uuid) -> SendResponseModel {
        SendResponseModel {
            object: Some("send".to_string()),
            id: Some(id),
            access_id: Some("access_id".to_string()),
            r#type: Some(SendType::Text),
            name: Some(TEST_ENC_STRING.to_string()),
            notes: None,
            file: None,
            text: None,
            key: Some(KEY_ENC_STRING.to_string()),
            max_access_count: None,
            access_count: Some(0),
            password: None,
            disabled: Some(false),
            revision_date: Some("2024-01-01T00:00:00Z".to_string()),
            expiration_date: None,
            deletion_date: Some("2024-12-31T00:00:00Z".to_string()),
            hide_email: Some(false),
            auth_type: None,
            emails: None,
        }
    }

    fn create_test_user_decryption() -> UserDecryptionResponseModel {
        UserDecryptionResponseModel {
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
        }
    }

    fn create_test_profile(user_id: uuid::Uuid) -> ProfileResponseModel {
        ProfileResponseModel {
            id: Some(user_id),
            account_keys: Some(Box::new(PrivateKeysResponseModel {
                object: None,
                signature_key_pair: None,
                public_key_encryption_key_pair: Box::new(PublicKeyEncryptionKeyPairResponseModel {
                    object: None,
                    wrapped_private_key: Some(TEST_ENC_STRING.to_string()),
                    public_key: None,
                    signed_public_key: None,
                }),
                security_state: None,
            })),
            ..ProfileResponseModel::default()
        }
    }

    fn create_test_sync_response(user_id: uuid::Uuid) -> SyncResponseModel {
        SyncResponseModel {
            object: Some("sync".to_string()),
            profile: Some(Box::new(create_test_profile(user_id))),
            folders: Some(vec![create_test_folder(uuid::Uuid::new_v4())]),
            ciphers: Some(vec![create_test_cipher(uuid::Uuid::new_v4())]),
            sends: Some(vec![create_test_send(uuid::Uuid::new_v4())]),
            user_decryption: Some(Box::new(create_test_user_decryption())),
            ..Default::default()
        }
    }

    fn create_test_key_rotation_data_response(
        org_id: uuid::Uuid,
        ea_id: uuid::Uuid,
        grantee_id: uuid::Uuid,
        device_id: uuid::Uuid,
        passkey_id: uuid::Uuid,
    ) -> KeyRotationDataResponseModel {
        KeyRotationDataResponseModel {
            object: Some("keyRotationData".to_string()),
            organization_password_reset_key_data: Some(vec![
                OrganizationPasswordResetKeyDataResponseModel {
                    object: Some("organizationPasswordResetKeyData".to_string()),
                    organization_id: Some(org_id),
                    organization_name: Some("Test Org".to_string()),
                    organization_public_key: Some(test_public_key_b64()),
                },
            ]),
            emergency_access_key_data: Some(vec![EmergencyAccessKeyDataResponseModel {
                object: Some("emergencyAccessKeyData".to_string()),
                id: Some(ea_id),
                grantee_id: Some(grantee_id),
                grantee_name: Some("Emergency Contact".to_string()),
                grantee_email: Some("contact@example.com".to_string()),
                public_key: Some(test_public_key_b64()),
            }]),
            trusted_device_key_data: Some(vec![TrustedDeviceKeyDataResponseModel {
                object: Some("trustedDeviceKeyData".to_string()),
                id: Some(device_id),
                encrypted_public_key: Some(TEST_ENC_STRING.to_string()),
                encrypted_user_key: Some(TEST_UNSIGNED_SHARED_KEY.to_string()),
            }]),
            passkey_key_data: Some(vec![PasskeyKeyDataResponseModel {
                object: Some("passkeyKeyData".to_string()),
                id: Some(passkey_id),
                encrypted_public_key: Some(TEST_ENC_STRING.to_string()),
                encrypted_user_key: Some(TEST_UNSIGNED_SHARED_KEY.to_string()),
            }]),
        }
    }

    #[tokio::test]
    async fn test_get_key_rotation_data_success() {
        let org_id = uuid::Uuid::new_v4();
        let ea_id = uuid::Uuid::new_v4();
        let grantee_id = uuid::Uuid::new_v4();
        let device_id = uuid::Uuid::new_v4();
        let passkey_id = uuid::Uuid::new_v4();

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_get_key_rotation_data()
                .once()
                .returning(move || {
                    Ok(create_test_key_rotation_data_response(
                        org_id, ea_id, grantee_id, device_id, passkey_id,
                    ))
                });
        });

        let data = get_key_rotation_data(&api_client).await.unwrap();

        assert_eq!(data.organization_memberships.len(), 1);
        assert_eq!(data.organization_memberships[0].organization_id, org_id);
        assert_eq!(data.organization_memberships[0].name, "Test Org");

        assert_eq!(data.emergency_access_memberships.len(), 1);
        assert_eq!(data.emergency_access_memberships[0].id, ea_id);
        assert_eq!(data.emergency_access_memberships[0].grantee_id, grantee_id);
        assert_eq!(
            data.emergency_access_memberships[0].name,
            "Emergency Contact"
        );

        assert_eq!(data.trusted_devices.len(), 1);
        assert_eq!(data.trusted_devices[0].id, device_id);
        assert_eq!(
            data.trusted_devices[0].encrypted_public_key.to_string(),
            TEST_ENC_STRING
        );
        assert_eq!(
            data.trusted_devices[0].encrypted_user_key.to_string(),
            TEST_UNSIGNED_SHARED_KEY
        );

        assert_eq!(data.passkeys.len(), 1);
        assert_eq!(data.passkeys[0].id, passkey_id);
        assert_eq!(
            data.passkeys[0].encrypted_public_key.to_string(),
            TEST_ENC_STRING
        );
        assert_eq!(
            data.passkeys[0].encrypted_user_key.to_string(),
            TEST_UNSIGNED_SHARED_KEY
        );

        let expected_public_key = PublicKey::from_der(&SpkiPublicKeyBytes::from(
            TEST_RSA_PUBLIC_KEY_BYTES.to_vec(),
        ))
        .unwrap();
        assert_eq!(
            data.organization_memberships[0]
                .public_key
                .to_der()
                .unwrap(),
            expected_public_key.to_der().unwrap()
        );
        assert_eq!(
            data.emergency_access_memberships[0]
                .public_key
                .to_der()
                .unwrap(),
            expected_public_key.to_der().unwrap()
        );

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_key_management_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_get_key_rotation_data_network_error() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_get_key_rotation_data()
                .once()
                .returning(move || {
                    Err(serde_json::Error::io(std::io::Error::other("Network error")).into())
                });
        });

        let result = get_key_rotation_data(&api_client).await;
        assert!(matches!(result, Err(SyncError::Network)));

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_key_management_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_get_key_rotation_data_empty_arrays_returns_empty_data() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_get_key_rotation_data()
                .once()
                .returning(move || {
                    // The server returns the entity arrays as present but empty when the user
                    // has no entries that participate in key rotation.
                    Ok(KeyRotationDataResponseModel {
                        object: Some("keyRotationData".to_string()),
                        organization_password_reset_key_data: Some(vec![]),
                        emergency_access_key_data: Some(vec![]),
                        trusted_device_key_data: Some(vec![]),
                        passkey_key_data: Some(vec![]),
                    })
                });
        });

        let data = get_key_rotation_data(&api_client).await.unwrap();

        assert!(data.organization_memberships.is_empty());
        assert!(data.emergency_access_memberships.is_empty());
        assert!(data.trusted_devices.is_empty());
        assert!(data.passkeys.is_empty());

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_key_management_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_get_key_rotation_data_missing_field_is_data_error() {
        let device_id = uuid::Uuid::new_v4();
        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_get_key_rotation_data()
                .once()
                .returning(move || {
                    Ok(KeyRotationDataResponseModel {
                        object: Some("keyRotationData".to_string()),
                        organization_password_reset_key_data: Some(vec![]),
                        emergency_access_key_data: Some(vec![]),
                        trusted_device_key_data: Some(vec![TrustedDeviceKeyDataResponseModel {
                            object: Some("trustedDeviceKeyData".to_string()),
                            id: Some(device_id),
                            encrypted_public_key: Some(TEST_ENC_STRING.to_string()),
                            // The required encrypted user key is missing.
                            encrypted_user_key: None,
                        }]),
                        passkey_key_data: Some(vec![]),
                    })
                });
        });

        let result = get_key_rotation_data(&api_client).await;
        assert!(matches!(result, Err(SyncError::Data)));

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_key_management_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_get_key_rotation_data_emergency_access_name_fallback() {
        let ea_id_email = uuid::Uuid::new_v4();
        let ea_id_unknown = uuid::Uuid::new_v4();
        let grantee_id = uuid::Uuid::new_v4();

        let api_client = ApiClient::new_mocked(|mock| {
            mock.accounts_key_management_api
                .expect_get_key_rotation_data()
                .once()
                .returning(move || {
                    Ok(KeyRotationDataResponseModel {
                        object: Some("keyRotationData".to_string()),
                        organization_password_reset_key_data: Some(vec![]),
                        emergency_access_key_data: Some(vec![
                            EmergencyAccessKeyDataResponseModel {
                                object: Some("emergencyAccessKeyData".to_string()),
                                id: Some(ea_id_email),
                                grantee_id: Some(grantee_id),
                                // No name set, so the email is used as the display name.
                                grantee_name: None,
                                grantee_email: Some("fallback@example.com".to_string()),
                                public_key: Some(test_public_key_b64()),
                            },
                            EmergencyAccessKeyDataResponseModel {
                                object: Some("emergencyAccessKeyData".to_string()),
                                id: Some(ea_id_unknown),
                                grantee_id: Some(grantee_id),
                                // Neither name nor email is set, so "Unknown" is used.
                                grantee_name: None,
                                grantee_email: None,
                                public_key: Some(test_public_key_b64()),
                            },
                        ]),
                        trusted_device_key_data: Some(vec![]),
                        passkey_key_data: Some(vec![]),
                    })
                });
        });

        let data = get_key_rotation_data(&api_client).await.unwrap();
        assert_eq!(data.emergency_access_memberships.len(), 2);
        assert_eq!(
            data.emergency_access_memberships[0].name,
            "fallback@example.com"
        );
        assert_eq!(data.emergency_access_memberships[1].name, "Unknown");

        if let ApiClient::Mock(mut mock) = api_client {
            mock.accounts_key_management_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_sync_current_account_data_success() {
        let user_id = uuid::Uuid::new_v4();
        let org_id = uuid::Uuid::new_v4();
        let ea_id = uuid::Uuid::new_v4();
        let grantee_id = uuid::Uuid::new_v4();
        let device_id = uuid::Uuid::new_v4();
        let passkey_id = uuid::Uuid::new_v4();
        let folder_id = uuid::Uuid::new_v4();
        let cipher_id = uuid::Uuid::new_v4();
        let send_id = uuid::Uuid::new_v4();

        let api_client = ApiClient::new_mocked(|mock| {
            mock.sync_api
                .expect_get()
                .once()
                .returning(move |_exclude_domains| {
                    let mut response = create_test_sync_response(user_id);
                    response.folders = Some(vec![create_test_folder(folder_id)]);
                    response.ciphers = Some(vec![create_test_cipher(cipher_id)]);
                    response.sends = Some(vec![create_test_send(send_id)]);
                    Ok(response)
                });
            mock.accounts_key_management_api
                .expect_get_key_rotation_data()
                .once()
                .returning(move || {
                    Ok(create_test_key_rotation_data_response(
                        org_id, ea_id, grantee_id, device_id, passkey_id,
                    ))
                });
        });

        let result = sync_current_account_data(&api_client).await;
        let data = result.unwrap();

        // Verify folders
        assert_eq!(data.folders.len(), 1);
        assert_eq!(data.folders[0].id, Some(FolderId::new(folder_id)));
        assert_eq!(data.folders[0].name, TEST_ENC_STRING.parse().unwrap());

        // Verify ciphers
        assert_eq!(data.ciphers.len(), 1);
        assert_eq!(data.ciphers[0].id, Some(CipherId::new(cipher_id)));
        assert_eq!(data.ciphers[0].name, Some(TEST_ENC_STRING.parse().unwrap()));

        // Verify sends
        assert_eq!(data.sends.len(), 1);
        assert_eq!(data.sends[0].id, Some(SendId::new(send_id)));
        assert_eq!(data.sends[0].name, TEST_ENC_STRING.parse().unwrap());
        assert_eq!(data.sends[0].key, KEY_ENC_STRING.parse().unwrap());

        assert_eq!(data.organization_memberships.len(), 1);
        assert_eq!(data.organization_memberships[0].organization_id, org_id);
        assert_eq!(data.emergency_access_memberships.len(), 1);
        assert_eq!(data.emergency_access_memberships[0].id, ea_id);
        assert_eq!(data.trusted_devices.len(), 1);
        assert_eq!(data.trusted_devices[0].id, device_id);
        assert_eq!(data.passkeys.len(), 1);
        assert_eq!(data.passkeys[0].id, passkey_id);
        assert!(data.kdf_and_salt.is_some());
        let (kdf, salt) = data.kdf_and_salt.unwrap();
        assert_eq!(salt, "test_salt");
        assert!(matches!(kdf, Kdf::PBKDF2 { iterations } if iterations.get() == 600000));
        assert!(matches!(
            data.wrapped_account_cryptographic_state,
            WrappedAccountCryptographicState::V1 { .. }
        ));

        if let ApiClient::Mock(mut mock) = api_client {
            mock.sync_api.checkpoint();
            mock.accounts_key_management_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_sync_current_account_data_network_error() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.sync_api
                .expect_get()
                .once()
                .returning(move |_exclude_domains| {
                    Err(serde_json::Error::io(std::io::Error::other("API error")).into())
                });
            mock.accounts_key_management_api
                .expect_get_key_rotation_data()
                .never();
        });

        let result = sync_current_account_data(&api_client).await;

        assert!(matches!(result, Err(SyncError::Network)));

        if let ApiClient::Mock(mut mock) = api_client {
            mock.sync_api.checkpoint();
            mock.accounts_key_management_api.checkpoint();
        }
    }

    #[test]
    fn test_parse_ciphers_filters_organization_ciphers() {
        let personal_cipher_id = uuid::Uuid::new_v4();
        let organization_cipher_id = uuid::Uuid::new_v4();

        let personal_cipher = create_test_cipher(personal_cipher_id);
        let mut organization_cipher = create_test_cipher(organization_cipher_id);
        organization_cipher.organization_id = Some(uuid::Uuid::new_v4());

        let ciphers = parse_ciphers(Some(vec![personal_cipher, organization_cipher])).unwrap();

        assert_eq!(ciphers.len(), 1);
        assert_eq!(ciphers[0].id, Some(CipherId::new(personal_cipher_id)));
    }
}

//! Functionality for syncing the latest account data from the server
use std::str::FromStr;

use bitwarden_api_api::apis::ApiClient;
use bitwarden_core::key_management::{
    SignedSecurityState, account_cryptographic_state::WrappedAccountCryptographicState,
};
use bitwarden_crypto::{
    EncString, Kdf, PublicKey, SignedPublicKey, SpkiPublicKeyBytes, UnsignedSharedKey,
};
use bitwarden_encoding::B64;
use bitwarden_error::bitwarden_error;
use bitwarden_vault::{Cipher, Folder};
use thiserror::Error;
use tokio::try_join;
use tracing::{debug, debug_span, info, instrument};
use uuid::Uuid;

use crate::key_rotation::{
    partial_rotateable_keyset::PartialRotateableKeyset,
    unlock::{V1EmergencyAccessMembership, V1OrganizationMembership},
};

#[allow(unused)]
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
    pub(super) user_id: uuid::Uuid,
}

#[allow(unused)]
#[derive(Debug, Error)]
#[bitwarden_error(flat)]
pub(super) enum SyncError {
    #[error("Network error during sync")]
    NetworkError,
    #[error("Failed to parse sync data")]
    DataError,
}

#[allow(unused)]
/// Fetch the public key for an organization
async fn fetch_organization_public_key(
    api_client: &ApiClient,
    organization_id: Uuid,
) -> Result<PublicKey, SyncError> {
    let org_details = api_client
        .organizations_api()
        .get_public_key(&organization_id.to_string())
        .await
        .map_err(|_| SyncError::NetworkError)?
        .public_key
        .ok_or(SyncError::DataError)?;
    PublicKey::from_der(&SpkiPublicKeyBytes::from(
        B64::from_str(&org_details)
            .map_err(|_| SyncError::DataError)?
            .into_bytes(),
    ))
    .map_err(|_| SyncError::DataError)
}

#[allow(unused)]
// Download the public keys for the organizations, since these are not included in the sync
pub(crate) async fn sync_orgs(
    api_client: &ApiClient,
) -> Result<Vec<V1OrganizationMembership>, SyncError> {
    let organizations = api_client
        .organizations_api()
        .get_user()
        .await
        .map_err(|_| SyncError::NetworkError)?
        .data
        .ok_or(SyncError::DataError)?
        .into_iter();
    let organizations = organizations
        .into_iter()
        .map(async |org| {
            let id = org.id.ok_or(SyncError::DataError)?;
            let public_key = fetch_organization_public_key(api_client, id).await?;
            Ok(V1OrganizationMembership {
                organization_id: id,
                name: org.name.ok_or(SyncError::DataError)?,
                public_key,
            })
        })
        .collect::<Vec<_>>();

    // Await all fetches
    let mut organization_memberships = Vec::new();
    for futures in organizations {
        organization_memberships.push(futures.await?);
    }

    info!(
        "Downloaded {} organization memberships",
        organization_memberships.len()
    );
    Ok(organization_memberships)
}

#[allow(unused)]
/// Fetch the public key for a user (used for emergency access)
async fn fetch_user_public_key(
    api_client: &ApiClient,
    user_id: Uuid,
) -> Result<PublicKey, SyncError> {
    let user_key_response = api_client
        .users_api()
        .get_public_key(user_id)
        .await
        .map_err(|_| SyncError::NetworkError)?;
    let public_key_b64 = user_key_response.public_key.ok_or(SyncError::DataError)?;
    PublicKey::from_der(&SpkiPublicKeyBytes::from(
        B64::from_str(&public_key_b64)
            .map_err(|_| SyncError::DataError)?
            .into_bytes(),
    ))
    .map_err(|_| SyncError::DataError)
}

#[allow(unused)]
/// Download the emergency access memberships and their public keys
pub(crate) async fn sync_emergency_access(
    api_client: &ApiClient,
) -> Result<Vec<V1EmergencyAccessMembership>, SyncError> {
    let emergency_access = api_client
        .emergency_access_api()
        .get_contacts()
        .await
        .map_err(|_| SyncError::NetworkError)?
        .data
        .ok_or(SyncError::DataError)?
        .into_iter()
        .map(async |ea| {
            let user_id = ea.grantee_id.ok_or(SyncError::DataError)?;
            let public_key = fetch_user_public_key(api_client, user_id).await?;
            Ok(V1EmergencyAccessMembership {
                id: ea.id.ok_or(SyncError::DataError)?,
                name: ea.name.ok_or(SyncError::DataError)?,
                public_key,
            })
        })
        .collect::<Vec<_>>();

    // Await all fetches
    let mut emergency_access_memberships = Vec::new();
    for futures in emergency_access {
        emergency_access_memberships.push(futures.await?);
    }

    info!(
        "Downloaded {} emergency access memberships",
        emergency_access_memberships.len()
    );
    Ok(emergency_access_memberships)
}

#[allow(unused)]
/// Sync the user's passkeys
async fn sync_passkeys(api_client: &ApiClient) -> Result<Vec<PartialRotateableKeyset>, SyncError> {
    let passkeys = api_client
        .web_authn_api()
        .get()
        .await
        .map_err(|_| SyncError::NetworkError)?
        .data
        .ok_or(SyncError::DataError)?
        .into_iter()
        .map(|cred| {
            Ok(PartialRotateableKeyset {
                id: Uuid::from_str(&cred.id.ok_or(SyncError::DataError)?)
                    .map_err(|_| SyncError::DataError)?,
                encrypted_public_key: EncString::from_str(
                    &cred.encrypted_public_key.ok_or(SyncError::DataError)?,
                )
                .map_err(|_| SyncError::DataError)?,
                encrypted_user_key: UnsignedSharedKey::from_str(
                    &cred.encrypted_user_key.ok_or(SyncError::DataError)?,
                )
                .map_err(|_| SyncError::DataError)?,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    info!("Downloaded {} passkeys", passkeys.len());
    Ok(passkeys)
}

#[allow(unused)]
/// Sync the user's trusted devices
async fn sync_devices(api_client: &ApiClient) -> Result<Vec<PartialRotateableKeyset>, SyncError> {
    let trusted_devices = api_client
        .devices_api()
        .get_all()
        .await
        .map_err(|_| SyncError::NetworkError)?
        .data
        .ok_or(SyncError::DataError)?
        .into_iter()
        .filter(|device| device.is_trusted.unwrap_or(false))
        .map(|device| {
            Ok(PartialRotateableKeyset {
                id: device.id.ok_or(SyncError::DataError)?,
                encrypted_public_key: EncString::from_str(
                    &device.encrypted_public_key.ok_or(SyncError::DataError)?,
                )
                .map_err(|_| SyncError::DataError)?,
                encrypted_user_key: UnsignedSharedKey::from_str(
                    &device.encrypted_user_key.ok_or(SyncError::DataError)?,
                )
                .map_err(|_| SyncError::DataError)?,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    info!("Downloaded {} trusted devices", trusted_devices.len());
    Ok(trusted_devices)
}

#[allow(unused)]
fn parse_ciphers(
    ciphers: Option<Vec<bitwarden_api_api::models::CipherDetailsResponseModel>>,
) -> Result<Vec<Cipher>, SyncError> {
    let ciphers = ciphers
        .ok_or(SyncError::DataError)?
        .into_iter()
        .map(|c| {
            let _span = debug_span!("deserializing_cipher", cipher_id = ?c.id).entered();
            Cipher::try_from(c).map_err(|_| SyncError::DataError)
        })
        .collect::<Result<Vec<_>, _>>()?;
    info!("Deserialized {} ciphers", ciphers.len());
    Ok(ciphers)
}

#[allow(unused)]
fn parse_folders(
    folders: Option<Vec<bitwarden_api_api::models::FolderResponseModel>>,
) -> Result<Vec<Folder>, SyncError> {
    let folders = folders
        .ok_or(SyncError::DataError)?
        .into_iter()
        .map(|f| {
            let _span = debug_span!("deserializing_folder", folder_id = ?f.id).entered();
            Folder::try_from(f).map_err(|_| SyncError::DataError)
        })
        .collect::<Result<Vec<_>, _>>()?;
    info!("Deserialized {} folders", folders.len());
    Ok(folders)
}

#[allow(unused)]
fn parse_sends(
    sends: Option<Vec<bitwarden_api_api::models::SendResponseModel>>,
) -> Result<Vec<bitwarden_send::Send>, SyncError> {
    let sends = sends
        .ok_or(SyncError::DataError)?
        .into_iter()
        .map(|s| {
            let _span = debug_span!("deserializing_send", send_id = ?s.id).entered();
            bitwarden_send::Send::try_from(s).map_err(|_| SyncError::DataError)
        })
        .collect::<Result<Vec<_>, _>>()?;
    info!("Deserialized {} sends", sends.len());
    Ok(sends)
}

#[allow(unused)]
fn from_kdf(
    kdf: &bitwarden_api_api::models::MasterPasswordUnlockKdfResponseModel,
) -> Result<Kdf, ()> {
    Ok(match kdf.kdf_type {
        bitwarden_api_api::models::KdfType::PBKDF2_SHA256 => Kdf::PBKDF2 {
            iterations: std::num::NonZeroU32::new(kdf.iterations.try_into().map_err(|_| ())?)
                .ok_or(())?,
        },
        bitwarden_api_api::models::KdfType::Argon2id => {
            let memory = kdf.memory.ok_or(())?;
            let parallelism = kdf.parallelism.ok_or(())?;
            Kdf::Argon2id {
                iterations: std::num::NonZeroU32::new(kdf.iterations.try_into().map_err(|_| ())?)
                    .ok_or(())?,
                memory: std::num::NonZeroU32::new(memory.try_into().map_err(|_| ())?).ok_or(())?,
                parallelism: std::num::NonZeroU32::new(parallelism.try_into().map_err(|_| ())?)
                    .ok_or(())?,
            }
        }
    })
}

#[allow(unused)]
#[derive(Debug, Error)]
#[bitwarden_error(flat)]
enum PrivateKeysParsingError {
    #[error("Missing required field: {0}")]
    MissingField(String),
    #[error("Invalid format in private keys response")]
    InvalidFormat,
}

#[allow(unused)]
#[instrument(skip(private_keys_response), err)]
fn from_private_keys_response(
    private_keys_response: &bitwarden_api_api::models::PrivateKeysResponseModel,
) -> Result<WrappedAccountCryptographicState, PrivateKeysParsingError> {
    let is_v2 = private_keys_response.signature_key_pair.is_some();
    if is_v2 {
        let private_key = private_keys_response
            .public_key_encryption_key_pair
            .wrapped_private_key
            .as_ref()
            .map(|pk| EncString::from_str(pk).map_err(|_| PrivateKeysParsingError::InvalidFormat))
            .ok_or(PrivateKeysParsingError::MissingField(
                "private_key".to_string(),
            ))??;
        let signing_key = private_keys_response
            .signature_key_pair
            .as_ref()
            .and_then(|skp| skp.wrapped_signing_key.as_ref())
            .map(|s| EncString::from_str(s).map_err(|_| PrivateKeysParsingError::InvalidFormat))
            .ok_or(PrivateKeysParsingError::MissingField(
                "signing_key".to_string(),
            ))??;
        let signed_public_key = private_keys_response
            .public_key_encryption_key_pair
            .signed_public_key
            .as_ref()
            .map(|spk| {
                SignedPublicKey::from_str(spk).map_err(|_| PrivateKeysParsingError::InvalidFormat)
            })
            .ok_or(PrivateKeysParsingError::MissingField(
                "signed_public_key".to_string(),
            ))??;
        let security_state = private_keys_response
            .security_state
            .as_ref()
            .map(|ss| {
                SignedSecurityState::from_str(&ss.security_state.clone().unwrap_or_default())
                    .map_err(|_| PrivateKeysParsingError::InvalidFormat)
            })
            .ok_or(PrivateKeysParsingError::MissingField(
                "security_state".to_string(),
            ))??;
        Ok(WrappedAccountCryptographicState::V2 {
            private_key,
            signed_public_key: Some(signed_public_key),
            signing_key,
            security_state,
        })
    } else {
        // V1: Private key, security state
        let private_key = private_keys_response
            .public_key_encryption_key_pair
            .wrapped_private_key
            .as_ref()
            .map(|pk| EncString::from_str(pk).map_err(|_| PrivateKeysParsingError::InvalidFormat))
            .ok_or(PrivateKeysParsingError::MissingField(
                "private_key".to_string(),
            ))??;
        Ok(WrappedAccountCryptographicState::V1 { private_key })
    }
}

#[allow(unused)]
fn parse_kdf_and_salt(
    user_decryption: &Option<Box<bitwarden_api_api::models::UserDecryptionResponseModel>>,
) -> Result<Option<(Kdf, String)>, SyncError> {
    let master_password_unlock = user_decryption
        .as_ref()
        .ok_or(SyncError::DataError)?
        .master_password_unlock
        .clone()
        .ok_or(SyncError::DataError)?;

    let kdf = from_kdf(&master_password_unlock.kdf).map_err(|_| SyncError::DataError)?;
    let salt = master_password_unlock.salt.ok_or(SyncError::DataError)?;
    debug!("Parsed password KDF and salt from sync response");
    Ok(Some((kdf, salt)))
}

#[allow(unused)]
pub(super) async fn sync_current_account_data(
    api_client: &ApiClient,
) -> Result<SyncedAccountData, SyncError> {
    info!("Syncing latest vault state from server for key rotation");
    let sync = api_client
        .sync_api()
        .get(Some(true))
        .await
        .map_err(|_| SyncError::NetworkError)?;

    let profile = sync.profile.as_ref().ok_or(SyncError::DataError)?;
    let kdf_and_salt = parse_kdf_and_salt(&sync.user_decryption)?;
    let account_cryptographic_state = profile
        .account_keys
        .to_owned()
        .ok_or(SyncError::DataError)?;
    let ciphers = parse_ciphers(sync.ciphers)?;
    let folders = parse_folders(sync.folders)?;
    let sends = parse_sends(sync.sends)?;
    let wrapped_account_cryptographic_state =
        from_private_keys_response(&account_cryptographic_state)
            .map_err(|_| SyncError::DataError)?;
    let user_id = sync
        .profile
        .as_ref()
        .and_then(|p| p.id)
        .ok_or(SyncError::DataError)?;

    // Concurrently sync organization memberships, emergency access memberships, trusted devices,
    // and passkeys
    info!("Syncing additional data (organizations, emergency access, devices, passkeys)");
    let (organization_memberships, emergency_access_memberships, trusted_devices, passkeys) = try_join!(
        sync_orgs(api_client),
        sync_emergency_access(api_client),
        sync_devices(api_client),
        sync_passkeys(api_client),
    )?;

    Ok(SyncedAccountData {
        wrapped_account_cryptographic_state,
        folders,
        ciphers,
        sends,
        emergency_access_memberships,
        organization_memberships,
        trusted_devices,
        passkeys,
        kdf_and_salt,
        user_id,
    })
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{
        apis::ApiClient,
        models::{
            DeviceAuthRequestResponseModel, DeviceAuthRequestResponseModelListResponseModel,
            EmergencyAccessGranteeDetailsResponseModel,
            EmergencyAccessGranteeDetailsResponseModelListResponseModel, FolderResponseModel,
            KdfType, MasterPasswordUnlockKdfResponseModel, MasterPasswordUnlockResponseModel,
            OrganizationPublicKeyResponseModel, PrivateKeysResponseModel,
            ProfileOrganizationResponseModel, ProfileOrganizationResponseModelListResponseModel,
            ProfileResponseModel, PublicKeyEncryptionKeyPairResponseModel, SendResponseModel,
            SendType, SyncResponseModel, UserDecryptionResponseModel, UserKeyResponseModel,
            WebAuthnCredentialResponseModel, WebAuthnCredentialResponseModelListResponseModel,
        },
    };
    use bitwarden_encoding::B64;

    use super::*;

    const TEST_ENC_STRING: &str = "2.STIyTrfDZN/JXNDN9zNEMw==|NDLum8BHZpPNYhJo9ggSkg==|UCsCLlBO3QzdPwvMAWs2VVwuE6xwOx/vxOooPObqnEw=";
    const KEY_ENC_STRING: &str = "2.KLv/j0V4Ebs0dwyPdtt4vw==|Nczvv+DTkeP466cP/wMDnGK6W9zEIg5iHLhcuQG6s+M=|SZGsfuIAIaGZ7/kzygaVUau3LeOvJUlolENBOU+LX7g=";
    // UnsignedSharedKey (RSA type 4) format for encrypted_user_key in devices/passkeys
    const TEST_UNSIGNED_SHARED_KEY: &str = "4.AAAAAAAAAAAAAAAAAAAAAA==";

    // Valid RSA SPKI DER public key bytes (reused from bitwarden-auth registration tests)
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
            name: Some(TEST_ENC_STRING.to_string()),
            notes: None,
            login: None,
            card: None,
            identity: None,
            secure_note: None,
            ssh_key: None,
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
        }
    }

    #[test]
    fn test_parse_folders_success() {
        let folder_id = uuid::Uuid::new_v4();
        let folders = vec![create_test_folder(folder_id)];

        let result = parse_folders(Some(folders));

        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(
            parsed[0].id.expect("should have id").to_string(),
            folder_id.to_string()
        );
    }

    #[test]
    fn test_parse_folders_empty() {
        let result = parse_folders(Some(vec![]));

        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn test_parse_ciphers_success() {
        let cipher_id = uuid::Uuid::new_v4();
        let ciphers = vec![create_test_cipher(cipher_id)];

        let result = parse_ciphers(Some(ciphers));

        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(
            parsed[0].id.expect("should have id").to_string(),
            cipher_id.to_string()
        );
    }

    #[test]
    fn test_parse_ciphers_empty() {
        let result = parse_ciphers(Some(vec![]));

        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn test_parse_sends_success() {
        let send_id = uuid::Uuid::new_v4();
        let sends = vec![create_test_send(send_id)];

        let result = parse_sends(Some(sends));

        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].id.expect("should have id"), send_id);
    }

    #[test]
    fn test_parse_sends_empty() {
        let result = parse_sends(Some(vec![]));

        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn test_parse_kdf_and_salt_success() {
        let user_decryption = Some(Box::new(create_test_user_decryption()));

        let result = parse_kdf_and_salt(&user_decryption);

        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert!(parsed.is_some());
        let (kdf, salt) = parsed.expect("should have kdf and salt");
        assert_eq!(salt, "test_salt");
        assert!(matches!(kdf, Kdf::PBKDF2 { iterations } if iterations.get() == 600000));
    }

    // --- API response model builders ---

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
            collections: None,
            domains: None,
            policies: None,
            user_decryption: Some(Box::new(create_test_user_decryption())),
        }
    }

    fn create_test_org_list_response(
        org_id: uuid::Uuid,
    ) -> ProfileOrganizationResponseModelListResponseModel {
        ProfileOrganizationResponseModelListResponseModel {
            object: None,
            data: Some(vec![ProfileOrganizationResponseModel {
                id: Some(org_id),
                name: Some("Test Org".to_string()),
                ..ProfileOrganizationResponseModel::new()
            }]),
            continuation_token: None,
        }
    }

    fn create_test_org_public_key_response() -> OrganizationPublicKeyResponseModel {
        OrganizationPublicKeyResponseModel {
            object: None,
            public_key: Some(test_public_key_b64()),
        }
    }

    fn create_test_emergency_access_response(
        ea_id: uuid::Uuid,
        grantee_id: uuid::Uuid,
    ) -> EmergencyAccessGranteeDetailsResponseModelListResponseModel {
        EmergencyAccessGranteeDetailsResponseModelListResponseModel {
            object: None,
            data: Some(vec![EmergencyAccessGranteeDetailsResponseModel {
                id: Some(ea_id),
                grantee_id: Some(grantee_id),
                name: Some("Emergency Contact".to_string()),
                ..EmergencyAccessGranteeDetailsResponseModel::new()
            }]),
            continuation_token: None,
        }
    }

    fn create_test_user_key_response() -> UserKeyResponseModel {
        UserKeyResponseModel {
            object: None,
            user_id: None,
            public_key: Some(test_public_key_b64()),
        }
    }

    fn create_test_devices_response(
        device_id: uuid::Uuid,
    ) -> DeviceAuthRequestResponseModelListResponseModel {
        DeviceAuthRequestResponseModelListResponseModel {
            object: None,
            data: Some(vec![DeviceAuthRequestResponseModel {
                id: Some(device_id),
                is_trusted: Some(true),
                encrypted_user_key: Some(TEST_UNSIGNED_SHARED_KEY.to_string()),
                encrypted_public_key: Some(TEST_ENC_STRING.to_string()),
                ..DeviceAuthRequestResponseModel::new()
            }]),
            continuation_token: None,
        }
    }

    fn create_test_passkeys_response(
        passkey_id: uuid::Uuid,
    ) -> WebAuthnCredentialResponseModelListResponseModel {
        WebAuthnCredentialResponseModelListResponseModel {
            object: None,
            data: Some(vec![WebAuthnCredentialResponseModel {
                id: Some(passkey_id.to_string()),
                encrypted_user_key: Some(TEST_UNSIGNED_SHARED_KEY.to_string()),
                encrypted_public_key: Some(TEST_ENC_STRING.to_string()),
                ..WebAuthnCredentialResponseModel::new()
            }]),
            continuation_token: None,
        }
    }

    // --- API mock tests ---

    #[tokio::test]
    async fn test_sync_orgs_success() {
        let org_id = uuid::Uuid::new_v4();

        let api_client = ApiClient::new_mocked(|mock| {
            let org_id = org_id;
            mock.organizations_api
                .expect_get_user()
                .once()
                .returning(move || Ok(create_test_org_list_response(org_id)));
            mock.organizations_api
                .expect_get_public_key()
                .once()
                .returning(move |_id| Ok(create_test_org_public_key_response()));
        });

        let result = sync_orgs(&api_client).await;

        assert!(result.is_ok());
        let orgs = result.unwrap();
        assert_eq!(orgs.len(), 1);
        assert_eq!(orgs[0].organization_id, org_id);
        assert_eq!(orgs[0].name, "Test Org");

        if let ApiClient::Mock(mut mock) = api_client {
            mock.organizations_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_sync_orgs_network_error() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.organizations_api
                .expect_get_user()
                .once()
                .returning(move || {
                    Err(bitwarden_api_api::apis::Error::Serde(
                        serde_json::Error::io(std::io::Error::other("API error")),
                    ))
                });
            mock.organizations_api.expect_get_public_key().never();
        });

        let result = sync_orgs(&api_client).await;

        assert!(matches!(result, Err(SyncError::NetworkError)));

        if let ApiClient::Mock(mut mock) = api_client {
            mock.organizations_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_sync_emergency_access_success() {
        let ea_id = uuid::Uuid::new_v4();
        let grantee_id = uuid::Uuid::new_v4();

        let api_client = ApiClient::new_mocked(|mock| {
            let ea_id = ea_id;
            let grantee_id = grantee_id;
            mock.emergency_access_api
                .expect_get_contacts()
                .once()
                .returning(move || Ok(create_test_emergency_access_response(ea_id, grantee_id)));
            mock.users_api
                .expect_get_public_key()
                .once()
                .returning(move |_user_id| Ok(create_test_user_key_response()));
        });

        let result = sync_emergency_access(&api_client).await;

        assert!(result.is_ok());
        let eas = result.unwrap();
        assert_eq!(eas.len(), 1);
        assert_eq!(eas[0].id, ea_id);
        assert_eq!(eas[0].name, "Emergency Contact");

        if let ApiClient::Mock(mut mock) = api_client {
            mock.emergency_access_api.checkpoint();
            mock.users_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_sync_devices_success() {
        let device_id = uuid::Uuid::new_v4();

        let api_client = ApiClient::new_mocked(|mock| {
            let device_id = device_id;
            mock.devices_api
                .expect_get_all()
                .once()
                .returning(move || Ok(create_test_devices_response(device_id)));
        });

        let result = sync_devices(&api_client).await;

        assert!(result.is_ok());
        let devices = result.unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].id, device_id);

        if let ApiClient::Mock(mut mock) = api_client {
            mock.devices_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_sync_devices_filters_untrusted() {
        let trusted_id = uuid::Uuid::new_v4();
        let untrusted_id = uuid::Uuid::new_v4();

        let api_client = ApiClient::new_mocked(|mock| {
            let trusted_id = trusted_id;
            let untrusted_id = untrusted_id;
            mock.devices_api.expect_get_all().once().returning(move || {
                Ok(DeviceAuthRequestResponseModelListResponseModel {
                    object: None,
                    data: Some(vec![
                        DeviceAuthRequestResponseModel {
                            id: Some(trusted_id),
                            is_trusted: Some(true),
                            encrypted_user_key: Some(TEST_UNSIGNED_SHARED_KEY.to_string()),
                            encrypted_public_key: Some(TEST_ENC_STRING.to_string()),
                            ..DeviceAuthRequestResponseModel::new()
                        },
                        DeviceAuthRequestResponseModel {
                            id: Some(untrusted_id),
                            is_trusted: Some(false),
                            encrypted_user_key: Some(TEST_UNSIGNED_SHARED_KEY.to_string()),
                            encrypted_public_key: Some(TEST_ENC_STRING.to_string()),
                            ..DeviceAuthRequestResponseModel::new()
                        },
                    ]),
                    continuation_token: None,
                })
            });
        });

        let result = sync_devices(&api_client).await;

        assert!(result.is_ok());
        let devices = result.unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].id, trusted_id);

        if let ApiClient::Mock(mut mock) = api_client {
            mock.devices_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_sync_passkeys_success() {
        let passkey_id = uuid::Uuid::new_v4();

        let api_client = ApiClient::new_mocked(|mock| {
            let passkey_id = passkey_id;
            mock.web_authn_api
                .expect_get()
                .once()
                .returning(move || Ok(create_test_passkeys_response(passkey_id)));
        });

        let result = sync_passkeys(&api_client).await;

        assert!(result.is_ok());
        let passkeys = result.unwrap();
        assert_eq!(passkeys.len(), 1);
        assert_eq!(passkeys[0].id, passkey_id);

        if let ApiClient::Mock(mut mock) = api_client {
            mock.web_authn_api.checkpoint();
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

        let api_client = ApiClient::new_mocked(|mock| {
            let user_id = user_id;
            mock.sync_api
                .expect_get()
                .once()
                .returning(move |_exclude_domains| Ok(create_test_sync_response(user_id)));

            let org_id = org_id;
            mock.organizations_api
                .expect_get_user()
                .once()
                .returning(move || Ok(create_test_org_list_response(org_id)));
            mock.organizations_api
                .expect_get_public_key()
                .once()
                .returning(move |_id| Ok(create_test_org_public_key_response()));

            let ea_id = ea_id;
            let grantee_id = grantee_id;
            mock.emergency_access_api
                .expect_get_contacts()
                .once()
                .returning(move || Ok(create_test_emergency_access_response(ea_id, grantee_id)));
            mock.users_api
                .expect_get_public_key()
                .once()
                .returning(move |_user_id| Ok(create_test_user_key_response()));

            let device_id = device_id;
            mock.devices_api
                .expect_get_all()
                .once()
                .returning(move || Ok(create_test_devices_response(device_id)));

            let passkey_id = passkey_id;
            mock.web_authn_api
                .expect_get()
                .once()
                .returning(move || Ok(create_test_passkeys_response(passkey_id)));
        });

        let result = sync_current_account_data(&api_client).await;

        assert!(result.is_ok());
        let data = result.unwrap();

        assert_eq!(data.user_id, user_id);
        assert_eq!(data.folders.len(), 1);
        assert_eq!(data.ciphers.len(), 1);
        assert_eq!(data.sends.len(), 1);
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
            mock.organizations_api.checkpoint();
            mock.emergency_access_api.checkpoint();
            mock.users_api.checkpoint();
            mock.devices_api.checkpoint();
            mock.web_authn_api.checkpoint();
        }
    }

    #[tokio::test]
    async fn test_sync_current_account_data_network_error() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.sync_api
                .expect_get()
                .once()
                .returning(move |_exclude_domains| {
                    Err(bitwarden_api_api::apis::Error::Serde(
                        serde_json::Error::io(std::io::Error::other("API error")),
                    ))
                });
            mock.organizations_api.expect_get_user().never();
            mock.organizations_api.expect_get_public_key().never();
            mock.emergency_access_api.expect_get_contacts().never();
            mock.users_api.expect_get_public_key().never();
            mock.devices_api.expect_get_all().never();
            mock.web_authn_api.expect_get().never();
        });

        let result = sync_current_account_data(&api_client).await;

        assert!(matches!(result, Err(SyncError::NetworkError)));

        if let ApiClient::Mock(mut mock) = api_client {
            mock.sync_api.checkpoint();
            mock.organizations_api.checkpoint();
            mock.emergency_access_api.checkpoint();
            mock.users_api.checkpoint();
            mock.devices_api.checkpoint();
            mock.web_authn_api.checkpoint();
        }
    }
}

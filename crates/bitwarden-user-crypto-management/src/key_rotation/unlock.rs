//! Functionality for re-encrypting unlock (decryption) methods during user key rotation.
//! During key-rotation, a new user-key is sampled. The unlock module then creates a set of newly
//! encrypted copies, one for each decryption/unlock method.

use core::panic;

use bitwarden_api_api::models::{
    self, EmergencyAccessWithIdRequestModel, MasterPasswordUnlockAndAuthenticationDataModel,
    OtherDeviceKeysUpdateRequestModel, ResetPasswordWithOrgIdRequestModel, UnlockDataRequestModel,
    WebAuthnLoginRotateKeyRequestModel,
};
use bitwarden_core::key_management::{
    KeyIds, MasterPasswordAuthenticationData, MasterPasswordUnlockData, SymmetricKeyId,
};
use bitwarden_crypto::{Kdf, KeyStoreContext, PublicKey, UnsignedSharedKey};
use serde::{Deserialize, Serialize};
use tracing::debug_span;
#[cfg(feature = "wasm")]
use tsify::Tsify;

use crate::key_rotation::partial_rotateable_keyset::PartialRotateableKeyset;

/// The unlock method that uses the master-key field on the user's account. This can be either
/// the master password, or the key-connector. For TDE users without a master password, this field
/// is empty.
pub(super) enum MasterkeyUnlockMethod {
    /// The master password based unlock method.
    Password {
        password: String,
        hint: Option<String>,
        kdf: Kdf,
        salt: String,
    },
    /// The key-connector based unlock method.
    /// NOTE: THIS IS NOT SUPPORTED YET AND WILL PANIC IF USED
    KeyConnector,
    /// No master-key based unlock method. This is TDE users without a master password.
    /// NOTE: THIS IS NOT SUPPORTED YET AND WILL PANIC IF USED
    None,
}

/// The data necessary to re-share the user-key to a V1 emergency access membership. Note: The
/// Public-key must be verified/trusted. Further, there is no sender authentication possible here.
#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct V1EmergencyAccessMembership {
    pub id: uuid::Uuid,
    pub name: String,
    pub public_key: PublicKey,
}

/// The data necessary to re-share the user-key to a V1 organization membership. Note: The
/// Public-key must be verified/trusted. Further, there is no sender authentication possible here.
#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct V1OrganizationMembership {
    pub organization_id: uuid::Uuid,
    pub name: String,
    pub public_key: PublicKey,
}

#[derive(Debug)]
pub(super) enum ReencryptError {
    /// Failed to update the unlock data for the master password
    MasterPasswordDerivation,
    /// Failed to update the unlock data for TDE/PRF-Passkey
    KeysetUnlockDataReencryption,
    /// Failed to update the unlock data for emergency access or organization membership
    KeySharingError,
}

/// Input data for re-encrypting unlock methods during user key rotation.
pub(super) struct ReencryptUnlockInput {
    /// The master-key based unlock method.
    pub(super) master_key_unlock_method: MasterkeyUnlockMethod,
    /// The trusted device keysets.
    pub(super) trusted_devices: Vec<PartialRotateableKeyset>,
    /// The webauthn credential keysets.
    pub(super) webauthn_credentials: Vec<PartialRotateableKeyset>,
    /// The V1 organization memberships.
    pub(super) trusted_organization_keys: Vec<V1OrganizationMembership>,
    /// The V1 emergency access memberships.
    pub(super) trusted_emergency_access_keys: Vec<V1EmergencyAccessMembership>,
}

/// Update the unlock methods for the updated user-key.
pub(super) fn reencrypt_unlock(
    input: ReencryptUnlockInput,
    current_user_key_id: SymmetricKeyId,
    new_user_key_id: SymmetricKeyId,
    ctx: &mut KeyStoreContext<KeyIds>,
) -> Result<UnlockDataRequestModel, ReencryptError> {
    let master_password_unlock_data = match input.master_key_unlock_method {
        MasterkeyUnlockMethod::Password {
            password,
            hint,
            kdf,
            salt,
        } => reencrypt_userkey_for_masterpassword_unlock(
            password,
            hint,
            kdf,
            salt,
            new_user_key_id,
            ctx,
        )?,
        MasterkeyUnlockMethod::KeyConnector => {
            panic!("KeyConnector based masterkey unlock method is not supported yet")
        }
        MasterkeyUnlockMethod::None => panic!("None masterkey unlock method is not supported yet"),
    };

    let tde_device_unlock_data = reencrypt_tde_devices(
        &input.trusted_devices,
        current_user_key_id,
        new_user_key_id,
        ctx,
    )?;
    let prf_passkey_unlock_data = reencrypt_passkey_credentials(
        &input.webauthn_credentials,
        current_user_key_id,
        new_user_key_id,
        ctx,
    )?;
    let emergency_accesses =
        reencrypt_emergency_access_keys(input.trusted_emergency_access_keys, new_user_key_id, ctx)?;
    let organizations_memberships =
        reencrypt_organization_memberships(input.trusted_organization_keys, new_user_key_id, ctx)?;

    Ok(UnlockDataRequestModel {
        master_password_unlock_data: Box::new(master_password_unlock_data),
        emergency_access_unlock_data: Some(emergency_accesses),
        organization_account_recovery_unlock_data: Some(organizations_memberships),
        passkey_unlock_data: Some(prf_passkey_unlock_data),
        device_key_unlock_data: Some(tde_device_unlock_data),
        v2_upgrade_token: None,
    })
}

/// Re-encrypt TDE device keys for the new user key.
fn reencrypt_tde_devices(
    trusted_devices: &[PartialRotateableKeyset],
    current_user_key_id: SymmetricKeyId,
    new_user_key_id: SymmetricKeyId,
    ctx: &mut KeyStoreContext<KeyIds>,
) -> Result<Vec<OtherDeviceKeysUpdateRequestModel>, ReencryptError> {
    trusted_devices
        .iter()
        .map(|device| {
            let _span = debug_span!("reencrypt_device_key", device_id = ?device.id).entered();
            device
                .rotate_userkey(current_user_key_id, new_user_key_id, ctx)
                .map_err(|_| ReencryptError::KeysetUnlockDataReencryption)
                .map(Into::into)
        })
        .collect()
}

/// Re-encrypt passkey (WebAuthn PRF) credentials for the new user key.
fn reencrypt_passkey_credentials(
    webauthn_credentials: &[PartialRotateableKeyset],
    current_user_key_id: SymmetricKeyId,
    new_user_key_id: SymmetricKeyId,
    ctx: &mut KeyStoreContext<KeyIds>,
) -> Result<Vec<WebAuthnLoginRotateKeyRequestModel>, ReencryptError> {
    webauthn_credentials
        .iter()
        .map(|cred| {
            let _span =
                debug_span!("reencrypt_webauthn_credential", credential_id = ?cred.id).entered();
            cred.rotate_userkey(current_user_key_id, new_user_key_id, ctx)
                .map_err(|_| ReencryptError::KeysetUnlockDataReencryption)
                .map(Into::into)
        })
        .collect()
}

/// Re-encrypt emergency access keys for the new user key.
fn reencrypt_emergency_access_keys(
    trusted_emergency_access_keys: Vec<V1EmergencyAccessMembership>,
    new_user_key_id: SymmetricKeyId,
    ctx: &mut KeyStoreContext<KeyIds>,
) -> Result<Vec<EmergencyAccessWithIdRequestModel>, ReencryptError> {
    trusted_emergency_access_keys
        .into_iter()
        .map(|ea| {
            let _span =
                debug_span!("reencrypt_emergency_access_key", grantee_id = ?ea.id).entered();
            // Share the key to the organization. Note: No sender authentication
            // and the passed in public-key must be verified/trusted.
            match UnsignedSharedKey::encapsulate(new_user_key_id, &ea.public_key, ctx) {
                Ok(reencrypted_key) => Ok(EmergencyAccessWithIdRequestModel {
                    r#type: models::EmergencyAccessType::Takeover,
                    wait_time_days: 0,
                    id: ea.id,
                    key_encrypted: reencrypted_key.to_string().into(),
                }),
                Err(_) => Err(ReencryptError::KeySharingError),
            }
        })
        .collect()
}

/// Re-encrypt organization membership keys for the new user key.
fn reencrypt_organization_memberships(
    trusted_organization_keys: Vec<V1OrganizationMembership>,
    new_user_key_id: SymmetricKeyId,
    ctx: &mut KeyStoreContext<KeyIds>,
) -> Result<Vec<ResetPasswordWithOrgIdRequestModel>, ReencryptError> {
    trusted_organization_keys
        .into_iter()
        .map(|org_membership| {
            let _span =
                debug_span!("reencrypt_organization_key", organization = ?org_membership.organization_id)
                    .entered();
            // Share the key to the organization. Note: No sender authentication
            // and the passed in public-key must be verified/trusted.
            match UnsignedSharedKey::encapsulate(new_user_key_id, &org_membership.public_key, ctx) {
                Ok(reencrypted_key) => Ok(ResetPasswordWithOrgIdRequestModel {
                    reset_password_key: Some(reencrypted_key.to_string()),
                    master_password_hash: None,
                    organization_id: org_membership.organization_id,
                }),
                Err(_) => Err(ReencryptError::KeySharingError),
            }
        })
        .collect()
}

fn reencrypt_userkey_for_masterpassword_unlock(
    password: String,
    hint: Option<String>,
    kdf: Kdf,
    salt: String,
    new_user_key_id: SymmetricKeyId,
    ctx: &mut KeyStoreContext<KeyIds>,
) -> Result<MasterPasswordUnlockAndAuthenticationDataModel, ReencryptError> {
    let _span = debug_span!("derive_master_password_unlock_data").entered();
    let unlock_data =
        MasterPasswordUnlockData::derive(&password, &kdf, &salt, new_user_key_id, ctx)
            .map_err(|_| ReencryptError::MasterPasswordDerivation)?;
    let authentication_data = MasterPasswordAuthenticationData::derive(&password, &kdf, &salt)
        .map_err(|_| ReencryptError::MasterPasswordDerivation)?;
    to_authentication_and_unlock_data(unlock_data, authentication_data, hint)
        .map_err(|_| ReencryptError::MasterPasswordDerivation)
}

#[derive(Debug)]
struct ParsingError;

fn to_authentication_and_unlock_data(
    master_password_unlock_data: MasterPasswordUnlockData,
    master_password_authentication_data: MasterPasswordAuthenticationData,
    hint: Option<String>,
) -> Result<MasterPasswordUnlockAndAuthenticationDataModel, ParsingError> {
    let (kdf_type, kdf_iterations, kdf_memory, kdf_parallelism) =
        match master_password_unlock_data.kdf {
            bitwarden_crypto::Kdf::PBKDF2 { iterations } => {
                (models::KdfType::PBKDF2_SHA256, iterations, None, None)
            }
            bitwarden_crypto::Kdf::Argon2id {
                iterations,
                memory,
                parallelism,
            } => (
                models::KdfType::Argon2id,
                iterations,
                Some(memory),
                Some(parallelism),
            ),
        };
    Ok(MasterPasswordUnlockAndAuthenticationDataModel {
        kdf_type,
        kdf_iterations: kdf_iterations.get().try_into().map_err(|_| ParsingError)?,
        kdf_memory: kdf_memory
            .map(|m| m.get().try_into().map_err(|_| ParsingError))
            .transpose()?,
        kdf_parallelism: kdf_parallelism
            .map(|p| p.get().try_into().map_err(|_| ParsingError))
            .transpose()?,
        email: Some(master_password_unlock_data.salt.clone()),
        master_key_authentication_hash: Some(
            master_password_authentication_data
                .master_password_authentication_hash
                .to_string(),
        ),
        master_key_encrypted_user_key: Some(
            master_password_unlock_data
                .master_key_wrapped_user_key
                .to_string(),
        ),
        master_password_hint: hint,
    })
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use bitwarden_api_api::models::KdfType;
    use bitwarden_core::key_management::KeyIds;
    use bitwarden_crypto::{Kdf, KeyStore, PublicKeyEncryptionAlgorithm, UnsignedSharedKey};
    use uuid::Uuid;

    use super::*;
    use crate::key_rotation::partial_rotateable_keyset::PartialRotateableKeyset;

    fn create_test_kdf_pbkdf2() -> Kdf {
        Kdf::PBKDF2 {
            iterations: NonZeroU32::new(600000).expect("valid iterations"),
        }
    }

    fn create_test_kdf_argon2id() -> Kdf {
        Kdf::Argon2id {
            iterations: NonZeroU32::new(3).expect("valid iterations"),
            memory: NonZeroU32::new(64).expect("valid memory"),
            parallelism: NonZeroU32::new(4).expect("valid parallelism"),
        }
    }

    fn create_test_unlock_data() -> MasterkeyUnlockMethod {
        let kdf = create_test_kdf_argon2id();
        let salt = "test@example.com".to_string();
        let password = "test_password".to_string();
        MasterkeyUnlockMethod::Password {
            password,
            hint: None,
            kdf,
            salt,
        }
    }

    fn assert_symmetric_keys_equal(
        key_id_1: SymmetricKeyId,
        key_id_2: SymmetricKeyId,
        ctx: &mut KeyStoreContext<KeyIds>,
    ) {
        #[allow(deprecated)]
        let key_1 = ctx
            .dangerous_get_symmetric_key(key_id_1)
            .expect("key 1 should exist");
        #[allow(deprecated)]
        let key_2 = ctx
            .dangerous_get_symmetric_key(key_id_2)
            .expect("key 2 should exist");
        assert_eq!(key_1, key_2, "symmetric keys should be equal");
    }

    #[test]
    fn test_to_authentication_and_unlock_data_pbkdf2() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();

        let kdf = create_test_kdf_pbkdf2();
        let salt = "test@example.com";
        let password = "test_password";

        let user_key_id = ctx.generate_symmetric_key();
        let unlock_data = MasterPasswordUnlockData::derive(password, &kdf, salt, user_key_id, &ctx)
            .expect("derive should succeed");
        let auth_data = MasterPasswordAuthenticationData::derive(password, &kdf, salt)
            .expect("derive should succeed");

        let result = to_authentication_and_unlock_data(unlock_data, auth_data, None);
        assert!(result.is_ok());

        let model = result.expect("should be ok");
        assert_eq!(model.kdf_type, KdfType::PBKDF2_SHA256);
        assert_eq!(model.kdf_iterations, 600000);
        assert!(model.kdf_memory.is_none());
        assert!(model.kdf_parallelism.is_none());
        assert_eq!(model.email, Some(salt.to_string()));
        assert!(model.master_key_authentication_hash.is_some());
        assert!(model.master_key_encrypted_user_key.is_some());
        assert!(model.master_password_hint.is_none());

        // Verify the unlock data can decrypt the user key
        let master_password_unlock_data = MasterPasswordUnlockData {
            master_key_wrapped_user_key: model
                .master_key_encrypted_user_key
                .expect("should be present")
                .parse()
                .expect("should parse"),
            kdf: kdf.clone(),
            salt: salt.to_string(),
        };
        let decrypted_user_key = master_password_unlock_data
            .unwrap_to_context(password, &mut ctx)
            .expect("unwrap should succeed");
        assert_symmetric_keys_equal(user_key_id, decrypted_user_key, &mut ctx);
    }

    #[test]
    fn test_to_authentication_and_unlock_data_argon2id() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();

        let kdf = create_test_kdf_argon2id();
        let salt = "test@example.com";
        let password = "test_password";

        let user_key_id = ctx.generate_symmetric_key();
        let unlock_data = MasterPasswordUnlockData::derive(password, &kdf, salt, user_key_id, &ctx)
            .expect("derive should succeed");
        let auth_data = MasterPasswordAuthenticationData::derive(password, &kdf, salt)
            .expect("derive should succeed");

        let result = to_authentication_and_unlock_data(unlock_data, auth_data, None);
        assert!(result.is_ok());

        let model = result.expect("should be ok");
        assert_eq!(model.kdf_type, KdfType::Argon2id);
        assert_eq!(model.kdf_iterations, 3);
        assert_eq!(model.kdf_memory, Some(64));
        assert_eq!(model.kdf_parallelism, Some(4));
        assert_eq!(model.email, Some(salt.to_string()));
        assert!(model.master_key_authentication_hash.is_some());
        assert!(model.master_key_encrypted_user_key.is_some());

        // Verify the unlock data can decrypt the user key
        let master_password_unlock_data = MasterPasswordUnlockData {
            master_key_wrapped_user_key: model
                .master_key_encrypted_user_key
                .expect("should be present")
                .parse()
                .expect("should parse"),
            kdf: kdf.clone(),
            salt: salt.to_string(),
        };
        let decrypted_user_key = master_password_unlock_data
            .unwrap_to_context(password, &mut ctx)
            .expect("unwrap should succeed");
        assert_symmetric_keys_equal(user_key_id, decrypted_user_key, &mut ctx);
    }

    #[test]
    fn test_reencrypt_unlock_device_key_data() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();

        let current_user_key_id = ctx.generate_symmetric_key();
        let new_user_key_id = ctx.generate_symmetric_key();
        let master_key_unlock_method = create_test_unlock_data();

        let (device_keyset, device_private_key) =
            PartialRotateableKeyset::make_test_keyset(current_user_key_id, &mut ctx);

        let result = reencrypt_unlock(
            ReencryptUnlockInput {
                master_key_unlock_method,
                trusted_devices: vec![device_keyset],
                webauthn_credentials: vec![],
                trusted_organization_keys: vec![],
                trusted_emergency_access_keys: vec![],
            },
            current_user_key_id,
            new_user_key_id,
            &mut ctx,
        );

        let unlock_data = result.expect("should be ok");

        let device_unlock = unlock_data
            .device_key_unlock_data
            .as_ref()
            .expect("should be present")
            .first()
            .expect("should have at least one");
        let decrypted_user_key = device_unlock
            .encrypted_user_key
            .parse::<UnsignedSharedKey>()
            .expect("should parse")
            .decapsulate(device_private_key, &mut ctx)
            .expect("unwrap should succeed");
        assert_symmetric_keys_equal(new_user_key_id, decrypted_user_key, &mut ctx);
    }

    #[test]
    fn test_reencrypt_unlock_webauthn_prf_credential_data() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();

        let current_user_key_id = ctx.generate_symmetric_key();
        let new_user_key_id = ctx.generate_symmetric_key();
        let master_key_unlock_method = create_test_unlock_data();

        let (credential_keyset, credential_private_key) =
            PartialRotateableKeyset::make_test_keyset(current_user_key_id, &mut ctx);

        let result = reencrypt_unlock(
            ReencryptUnlockInput {
                master_key_unlock_method,
                trusted_devices: vec![],
                webauthn_credentials: vec![credential_keyset],
                trusted_organization_keys: vec![],
                trusted_emergency_access_keys: vec![],
            },
            current_user_key_id,
            new_user_key_id,
            &mut ctx,
        );

        let unlock_data = result.expect("should be ok");

        // Ensure it decrypts to the correct key after rotation
        let credential_unlock = unlock_data
            .passkey_unlock_data
            .as_ref()
            .expect("should be present")
            .first()
            .expect("should have at least one");
        let decrypted_user_key = credential_unlock
            .encrypted_user_key
            .parse::<UnsignedSharedKey>()
            .expect("should parse")
            .decapsulate(credential_private_key, &mut ctx)
            .expect("unwrap should succeed");
        assert_symmetric_keys_equal(new_user_key_id, decrypted_user_key, &mut ctx);
    }

    #[test]
    fn test_reencrypt_unlock_emergency_access_data() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();

        let current_user_key_id = ctx.generate_symmetric_key();
        let new_user_key_id = ctx.generate_symmetric_key();
        let master_key_unlock_method = create_test_unlock_data();

        let organization_private_key =
            ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let emergency_access = V1EmergencyAccessMembership {
            id: Uuid::new_v4(),
            name: "Test User".to_string(),
            public_key: ctx
                .get_public_key(organization_private_key)
                .expect("key exists"),
        };

        let result = reencrypt_unlock(
            ReencryptUnlockInput {
                master_key_unlock_method,
                trusted_devices: vec![],
                webauthn_credentials: vec![],
                trusted_organization_keys: vec![],
                trusted_emergency_access_keys: vec![emergency_access],
            },
            current_user_key_id,
            new_user_key_id,
            &mut ctx,
        );

        let unlock_data = result.expect("should be ok");

        // Ensure it decrypts to the correct key after rotation
        let emergency_access_unlock = unlock_data
            .emergency_access_unlock_data
            .as_ref()
            .expect("should be present")
            .first()
            .expect("should have at least one");
        let decrypted_user_key = emergency_access_unlock
            .key_encrypted
            .as_ref()
            .map(|k| k.parse::<UnsignedSharedKey>())
            .expect("should be present")
            .expect("should parse")
            .decapsulate(organization_private_key, &mut ctx)
            .expect("unwrap should succeed");
        assert_symmetric_keys_equal(new_user_key_id, decrypted_user_key, &mut ctx);
    }

    #[test]
    fn test_reencrypt_unlock_organization_membership_data() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();

        let kdf = create_test_kdf_argon2id();
        let salt = "test@example.com".to_string();
        let password = "test_password".to_string();

        let current_user_key_id = ctx.generate_symmetric_key();
        let new_user_key_id = ctx.generate_symmetric_key();

        let org_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let org_membership = V1OrganizationMembership {
            organization_id: Uuid::new_v4(),
            name: "Test Org".to_string(),
            public_key: ctx.get_public_key(org_key).expect("key exists"),
        };

        // Note: Replace this with [`MasterkeyUnlockMethod::None`] when implemented.
        let master_key_unlock_method = MasterkeyUnlockMethod::Password {
            password: password.clone(),
            hint: None,
            kdf: kdf.clone(),
            salt: salt.clone(),
        };

        let result = reencrypt_unlock(
            ReencryptUnlockInput {
                master_key_unlock_method,
                trusted_devices: vec![],
                webauthn_credentials: vec![],
                trusted_organization_keys: vec![org_membership],
                trusted_emergency_access_keys: vec![],
            },
            current_user_key_id,
            new_user_key_id,
            &mut ctx,
        );

        let unlock_data = result.expect("should be ok");

        let org_membership_unlock = unlock_data
            .organization_account_recovery_unlock_data
            .as_ref()
            .expect("should be present")
            .first()
            .expect("should have at least one");
        let decrypted_user_key = org_membership_unlock
            .reset_password_key
            .as_ref()
            .map(|k| k.parse::<UnsignedSharedKey>())
            .expect("should be present")
            .expect("should parse")
            .decapsulate(org_key, &mut ctx)
            .expect("unwrap should succeed");
        assert_symmetric_keys_equal(new_user_key_id, decrypted_user_key, &mut ctx);
    }
}

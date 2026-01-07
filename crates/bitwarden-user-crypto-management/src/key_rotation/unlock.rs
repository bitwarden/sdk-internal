use bitwarden_api_api::models::{
    self, EmergencyAccessWithIdRequestModel, MasterPasswordUnlockAndAuthenticationDataModel,
    ResetPasswordWithOrgIdRequestModel, UnlockDataRequestModel,
};
use bitwarden_core::key_management::{
    KeyIds, MasterPasswordAuthenticationData, MasterPasswordUnlockData, SymmetricKeyId,
};
use bitwarden_crypto::{AsymmetricPublicCryptoKey, Kdf, KeyStoreContext, UnsignedSharedKey};
use tracing::debug_span;

use crate::key_rotation::rotateable_keyset::KeysetUnlockData;

/// The unlock method that uses the master-key field on the user's account. This can be either
/// the master password, or the key-connector. For TDE users without a master password, this field
/// is empty.
pub enum MasterkeyUnlockMethod {
    /// The master password based unlock method.
    Password {
        password: String,
        hint: Option<String>,
        kdf: Kdf,
        salt: String,
    },
    /// The key-connector based unlock method.
    KeyConnector,
    /// No master-key based unlock method. This is TDE users without a master password.
    None,
}

/// The data necessary to re-share the user-key to a V1 emergency access membership. Note: The
/// Public-key must be verified/trusted. Further, there is no sender authentication possible here.
#[derive(Clone)]
pub(super) struct V1EmergencyAccessMembership {
    pub(super) id: uuid::Uuid,
    pub(super) public_key: AsymmetricPublicCryptoKey,
}

/// The data necessary to re-share the user-key to a V1 organization membership. Note: The
/// Public-key must be verified/trusted. Further, there is no sender authentication possible here.
#[derive(Clone)]
pub(super) struct V1OrganizationMembership {
    pub(super) organization_id: uuid::Uuid,
    pub(super) public_key: AsymmetricPublicCryptoKey,
}

#[derive(Debug)]
pub(super) enum ReencryptError {
    MasterPasswordDerivation,
    KeysetUnlockDataReencryption,
}

/// Input data for re-encrypting unlock methods during user key rotation.
pub(super) struct ReencryptUnlockInput {
    /// The master-key based unlock method.
    pub(super) master_key_unlock_method: MasterkeyUnlockMethod,
    /// The trusted device keysets.
    pub(super) trusted_devices: Vec<KeysetUnlockData>,
    /// The webauthn credential keysets.
    pub(super) webauthn_credentials: Vec<KeysetUnlockData>,
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
    let master_password_unlock_and_authentication_data_model = match input.master_key_unlock_method
    {
        MasterkeyUnlockMethod::Password {
            password,
            hint,
            kdf,
            salt,
        } => {
            let _span = debug_span!("derive_master_password_unlock_data").entered();
            let unlock_data =
                MasterPasswordUnlockData::derive(&password, &kdf, &salt, new_user_key_id, ctx)
                    .map_err(|_| ReencryptError::MasterPasswordDerivation)?;
            let authentication_data =
                MasterPasswordAuthenticationData::derive(&password, &kdf, &salt)
                    .map_err(|_| ReencryptError::MasterPasswordDerivation)?;
            Some(to_authentication_and_unlock_data(
                unlock_data,
                authentication_data,
                hint,
            ))
        }
        MasterkeyUnlockMethod::KeyConnector => {
            tracing::error!("Key-connector based key rotation is not yet implemented");
            None
        }
        MasterkeyUnlockMethod::None => {
            tracing::error!("Key-rotation without master-key based unlock is not supported yet");
            None
        }
    };

    let devices: Vec<KeysetUnlockData> = {
        let _span = debug_span!("reencrypt_device_keys").entered();
        input
            .trusted_devices
            .iter()
            .map(|device| {
                let _span = debug_span!("reencrypt_device_key", device_id = ?device.id).entered();
                device
                    .reencrypt(current_user_key_id, new_user_key_id, ctx)
                    .map_err(|_| ReencryptError::KeysetUnlockDataReencryption)
            })
            .collect::<Result<Vec<KeysetUnlockData>, ReencryptError>>()?
    };
    let passkeys: Vec<KeysetUnlockData> = {
        let _span = debug_span!("reencrypt_webauthn_credentials").entered();
        input
            .webauthn_credentials
            .iter()
            .map(|cred| {
                let _span = debug_span!("reencrypt_webauthn_credential", credential_id = ?cred.id)
                    .entered();
                cred.reencrypt(current_user_key_id, new_user_key_id, ctx)
                    .map_err(|_| ReencryptError::KeysetUnlockDataReencryption)
            })
            .collect::<Result<Vec<KeysetUnlockData>, ReencryptError>>()?
    };
    let emergency_accesses = {
        let _span = debug_span!("reencrypt_emergency_access_keys").entered();
        input
            .trusted_emergency_access_keys
            .iter()
            .map(|ea| {
                let _span =
                    debug_span!("reencrypt_emergency_access_key", grantee_id = ?ea.id).entered();
                match UnsignedSharedKey::encapsulate(new_user_key_id, &ea.public_key, ctx) {
                    Ok(reencrypted_key) => Ok(EmergencyAccessWithIdRequestModel {
                        r#type: models::EmergencyAccessType::Takeover,
                        wait_time_days: 0,
                        id: ea.id,
                        key_encrypted: reencrypted_key.to_string().into(),
                    }),
                    Err(_) => Err(ReencryptError::KeysetUnlockDataReencryption),
                }
            })
            .collect::<Result<Vec<EmergencyAccessWithIdRequestModel>, ReencryptError>>()?
    };
    let organizations_memberships = input
        .trusted_organization_keys
        .into_iter()
        .filter_map(|org_membership| {
            // Share the key to the organization. Note: No sender authentication
            // and the passed in public-key must be verified/trusted.
            match UnsignedSharedKey::encapsulate(new_user_key_id, &org_membership.public_key, ctx) {
                Ok(reencrypted_key) => Some(ResetPasswordWithOrgIdRequestModel {
                    reset_password_key: Some(reencrypted_key.to_string()),
                    master_password_hash: None,
                    organization_id: org_membership.organization_id,
                }),
                Err(_) => None,
            }
        })
        .collect();

    Ok(UnlockDataRequestModel {
        master_password_unlock_data: Box::new(
            // This is safe for now until we support key-connector or no-master-key based rotation.
            master_password_unlock_and_authentication_data_model
                .expect("Master-password based unlock data must be present for re-encryption")
                .map_err(|_| ReencryptError::KeysetUnlockDataReencryption)?,
        ),
        emergency_access_unlock_data: Some(emergency_accesses),
        organization_account_recovery_unlock_data: Some(organizations_memberships),
        passkey_unlock_data: Some(passkeys.into_iter().map(Into::into).collect()),
        device_key_unlock_data: Some(devices.into_iter().map(Into::into).collect()),
    })
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
    use bitwarden_crypto::{Kdf, KeyStore, PrimitiveEncryptable, UnsignedSharedKey};
    use uuid::Uuid;

    use super::*;
    use crate::key_rotation::rotateable_keyset::KeysetUnlockData;

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
    }

    #[test]
    fn test_reencrypt_unlock_with_all_data() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();

        let kdf = create_test_kdf_argon2id();
        let salt = "test@example.com".to_string();
        let password = "test_password".to_string();

        let current_user_key_id = ctx.generate_symmetric_key();
        let new_user_key_id = ctx.generate_symmetric_key();

        // Create device keyset
        let device_private_key = ctx.make_asymmetric_key();
        let device_pubkey_der = ctx
            .get_public_key(device_private_key)
            .expect("key exists")
            .to_der()
            .expect("valid der");
        let device_encrypted_public_key = device_pubkey_der
            .encrypt(&mut ctx, current_user_key_id)
            .expect("encrypt works");
        let device_encrypted_user_key = UnsignedSharedKey::encapsulate(
            current_user_key_id,
            &ctx.get_public_key(device_private_key).expect("key exists"),
            &ctx,
        )
        .expect("encapsulate works");
        let device = KeysetUnlockData {
            id: Uuid::new_v4(),
            encrypted_public_key: device_encrypted_public_key,
            encrypted_user_key: device_encrypted_user_key,
        };

        // Create webauthn credential keyset
        let credential_private_key = ctx.make_asymmetric_key();
        let credential_pubkey_der = ctx
            .get_public_key(credential_private_key)
            .expect("key exists")
            .to_der()
            .expect("valid der");
        let credential_encrypted_public_key = credential_pubkey_der
            .encrypt(&mut ctx, current_user_key_id)
            .expect("encrypt works");
        let credential_encrypted_user_key = UnsignedSharedKey::encapsulate(
            current_user_key_id,
            &ctx.get_public_key(credential_private_key)
                .expect("key exists"),
            &ctx,
        )
        .expect("encapsulate works");
        let credential = KeysetUnlockData {
            id: Uuid::new_v4(),
            encrypted_public_key: credential_encrypted_public_key,
            encrypted_user_key: credential_encrypted_user_key,
        };

        // Create emergency access membership
        let ea_key = ctx.make_asymmetric_key();
        let emergency_access = V1EmergencyAccessMembership {
            id: Uuid::new_v4(),
            public_key: ctx.get_public_key(ea_key).expect("key exists"),
        };

        // Create organization membership
        let org_key = ctx.make_asymmetric_key();
        let org_membership = V1OrganizationMembership {
            organization_id: Uuid::new_v4(),
            public_key: ctx.get_public_key(org_key).expect("key exists"),
        };

        let master_key_unlock_method = MasterkeyUnlockMethod::Password {
            password: password.clone(),
            hint: None,
            kdf: kdf.clone(),
            salt: salt.clone(),
        };

        let result = reencrypt_unlock(
            ReencryptUnlockInput {
                master_key_unlock_method,
                trusted_devices: vec![device],
                webauthn_credentials: vec![credential],
                trusted_organization_keys: vec![org_membership],
                trusted_emergency_access_keys: vec![emergency_access],
            },
            current_user_key_id,
            new_user_key_id,
            &mut ctx,
        );

        assert!(result.is_ok());
        let unlock_data = result.expect("should be ok");

        // Verify all data was re-encrypted
        assert_eq!(
            unlock_data.master_password_unlock_data.kdf_type,
            KdfType::Argon2id
        );
        assert_eq!(
            unlock_data.master_password_unlock_data.email,
            Some(salt.clone())
        );
        assert_eq!(
            unlock_data
                .device_key_unlock_data
                .as_ref()
                .expect("present")
                .len(),
            1
        );
        assert_eq!(
            unlock_data
                .passkey_unlock_data
                .as_ref()
                .expect("present")
                .len(),
            1
        );
        assert_eq!(
            unlock_data
                .emergency_access_unlock_data
                .as_ref()
                .expect("present")
                .len(),
            1
        );
        assert_eq!(
            unlock_data
                .organization_account_recovery_unlock_data
                .as_ref()
                .expect("present")
                .len(),
            1
        );

        // Get the expected new user key for comparison
        #[expect(deprecated)]
        let expected_new_user_key = ctx
            .dangerous_get_symmetric_key(new_user_key_id)
            .expect("new user key exists")
            .clone();

        // Validate master password unlock: derive master key and decrypt user key
        let master_key_encrypted_user_key: bitwarden_crypto::EncString = unlock_data
            .master_password_unlock_data
            .master_key_encrypted_user_key
            .as_ref()
            .expect("master key encrypted user key exists")
            .parse()
            .expect("valid enc string");
        let mp_unlock_data = MasterPasswordUnlockData {
            kdf: kdf.clone(),
            salt: salt.clone(),
            master_key_wrapped_user_key: master_key_encrypted_user_key,
        };
        let unwrapped_user_key_id = mp_unlock_data
            .unwrap_to_context(&password, &mut ctx)
            .unwrap();
        #[expect(deprecated)]
        let unwrapped_user_key = ctx
            .dangerous_get_symmetric_key(unwrapped_user_key_id)
            .expect("key exists");
        assert_eq!(
            unwrapped_user_key, &expected_new_user_key,
            "Master password unlock should decrypt to the new user key"
        );

        // Validate device key unlock: use device private key to decrypt user key
        let device_unlock_data = &unlock_data
            .device_key_unlock_data
            .as_ref()
            .expect("device unlock data exists")[0];
        let device_encrypted_user_key: UnsignedSharedKey = device_unlock_data
            .encrypted_user_key
            .parse()
            .expect("valid unsigned shared key");
        let decrypted_user_key_from_device: bitwarden_core::key_management::SymmetricKeyId =
            device_encrypted_user_key
                .decapsulate(device_private_key, &mut ctx)
                .expect("decapsulate succeeds");
        #[expect(deprecated)]
        let decrypted_user_key_from_device = ctx
            .dangerous_get_symmetric_key(decrypted_user_key_from_device)
            .expect("key exists");
        assert_eq!(
            decrypted_user_key_from_device, &expected_new_user_key,
            "Device key unlock should decrypt to the new user key"
        );

        // Validate passkey unlock: use credential private key to decrypt user key
        let passkey_unlock_data = &unlock_data
            .passkey_unlock_data
            .as_ref()
            .expect("passkey unlock data exists")[0];
        let passkey_encrypted_user_key: UnsignedSharedKey = passkey_unlock_data
            .encrypted_user_key
            .parse()
            .expect("valid unsigned shared key");
        let decrypted_user_key_from_passkey: bitwarden_core::key_management::SymmetricKeyId =
            passkey_encrypted_user_key
                .decapsulate(credential_private_key, &mut ctx)
                .expect("decapsulate succeeds");
        #[expect(deprecated)]
        let decrypted_user_key_from_passkey = ctx
            .dangerous_get_symmetric_key(decrypted_user_key_from_passkey)
            .expect("key exists");
        assert_eq!(
            decrypted_user_key_from_passkey, &expected_new_user_key,
            "Passkey unlock should decrypt to the new user key"
        );

        // Validate emergency access unlock: use EA private key to decrypt user key
        let ea_unlock_data = &unlock_data
            .emergency_access_unlock_data
            .as_ref()
            .expect("emergency access unlock data exists")[0];
        let ea_encrypted_user_key: UnsignedSharedKey = ea_unlock_data
            .key_encrypted
            .as_ref()
            .expect("key encrypted exists")
            .parse()
            .expect("valid unsigned shared key");
        let decrypted_user_key_from_ea: bitwarden_core::key_management::SymmetricKeyId =
            ea_encrypted_user_key
                .decapsulate(ea_key, &mut ctx)
                .expect("decapsulate succeeds");
        #[expect(deprecated)]
        let decrypted_user_key_from_ea = ctx
            .dangerous_get_symmetric_key(decrypted_user_key_from_ea)
            .expect("key exists");
        assert_eq!(
            decrypted_user_key_from_ea, &expected_new_user_key,
            "Emergency access unlock should decrypt to the new user key"
        );

        // Validate organization account recovery unlock: use org private key to decrypt user key
        let org_unlock_data = &unlock_data
            .organization_account_recovery_unlock_data
            .as_ref()
            .expect("organization unlock data exists")[0];
        let org_encrypted_user_key: UnsignedSharedKey = org_unlock_data
            .reset_password_key
            .as_ref()
            .expect("reset password key exists")
            .parse()
            .expect("valid unsigned shared key");
        let decrypted_user_key_from_org: bitwarden_core::key_management::SymmetricKeyId =
            org_encrypted_user_key
                .decapsulate(org_key, &mut ctx)
                .expect("decapsulate succeeds");
        #[expect(deprecated)]
        let decrypted_user_key_from_org = ctx
            .dangerous_get_symmetric_key(decrypted_user_key_from_org)
            .expect("key exists");
        assert_eq!(
            decrypted_user_key_from_org, &expected_new_user_key,
            "Organization account recovery unlock should decrypt to the new user key"
        );
    }
}

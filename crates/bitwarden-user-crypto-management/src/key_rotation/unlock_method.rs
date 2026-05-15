//! Functionality for re-encrypting unlock method data during user key rotation.

use bitwarden_api_api::models::{self, UnlockMethodRequestModel};
use bitwarden_core::key_management::{KeySlotIds, MasterPasswordUnlockData, SymmetricKeySlotId};
use bitwarden_crypto::{Kdf, KeyConnectorKey, KeyStoreContext};

use crate::key_rotation::{
    RotateUserKeysError, rotate_user_keys::KeyRotationMethod, sync::SyncedAccountData,
    unlock::ReencryptError,
};

/// The primary unlock method for the account and the data needed to re-encrypt it under the new
/// user key.
pub(super) enum PrimaryUnlockMethod {
    /// The master password based unlock method.
    Password {
        password: String,
        kdf: Kdf,
        salt: String,
    },
    /// The Key Connector based unlock method.
    KeyConnector { key_connector_key: KeyConnectorKey },
    /// TDE based unlock method. TDE keys themselves are rotated as part of the
    /// common_unlock_data.
    Tde,
}

impl PrimaryUnlockMethod {
    pub(super) fn from_key_rotation_method(
        method: KeyRotationMethod,
        synced_account_data: &SyncedAccountData,
        key_connector_key: Option<KeyConnectorKey>,
    ) -> Result<Self, RotateUserKeysError> {
        match method {
            KeyRotationMethod::Password { password } => {
                let (kdf, salt) = synced_account_data
                    .kdf_and_salt
                    .clone()
                    .ok_or(RotateUserKeysError::Api)?;
                Ok(PrimaryUnlockMethod::Password {
                    password,
                    kdf,
                    salt,
                })
            }
            KeyRotationMethod::KeyConnector { .. } => {
                let key_connector_key =
                    key_connector_key.ok_or(RotateUserKeysError::KeyConnectorApi)?;
                Ok(PrimaryUnlockMethod::KeyConnector { key_connector_key })
            }
            KeyRotationMethod::Tde => Ok(PrimaryUnlockMethod::Tde),
        }
    }
}

/// Re-encrypt the unlock method data for the given input and new user key id.
pub(super) fn reencrypt_unlock_method_data(
    input: PrimaryUnlockMethod,
    new_user_key_id: SymmetricKeySlotId,
    ctx: &mut KeyStoreContext<KeySlotIds>,
) -> Result<UnlockMethodRequestModel, ReencryptError> {
    match input {
        PrimaryUnlockMethod::Password {
            password,
            kdf,
            salt,
        } => {
            let master_password_unlock_data =
                MasterPasswordUnlockData::derive(&password, &kdf, &salt, new_user_key_id, ctx)
                    .map_err(|_| ReencryptError::MasterPasswordDerivation)?;

            Ok(UnlockMethodRequestModel {
                unlock_method: models::UnlockMethod::MasterPassword,
                master_password_unlock_data: Some(Box::new((&master_password_unlock_data).into())),
                key_connector_key_wrapped_user_key: None,
            })
        }
        PrimaryUnlockMethod::KeyConnector { key_connector_key } => {
            let wrapped_user_key = key_connector_key
                .wrap_user_key(new_user_key_id, ctx)
                .map_err(|_| ReencryptError::KeyConnectorWrapping)?;

            Ok(UnlockMethodRequestModel {
                unlock_method: models::UnlockMethod::KeyConnector,
                master_password_unlock_data: None,
                key_connector_key_wrapped_user_key: Some(wrapped_user_key.to_string()),
            })
        }
        PrimaryUnlockMethod::Tde => Ok(UnlockMethodRequestModel {
            unlock_method: models::UnlockMethod::Tde,
            master_password_unlock_data: None,
            key_connector_key_wrapped_user_key: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use bitwarden_api_api::models::UnlockMethod;
    use bitwarden_core::key_management::{
        KeySlotIds, MasterPasswordUnlockData,
        account_cryptographic_state::WrappedAccountCryptographicState,
    };
    use bitwarden_crypto::{Kdf, KeyConnectorKey, KeyStore, KeyStoreContext};

    use super::*;
    use crate::key_rotation::{rotate_user_keys::KeyRotationMethod, sync::SyncedAccountData};

    fn make_synced_account_data(kdf_and_salt: Option<(Kdf, String)>) -> SyncedAccountData {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (_, wrapped_account_cryptographic_state) =
            WrappedAccountCryptographicState::make(&mut ctx)
                .expect("make wrapped account cryptographic state should succeed");
        SyncedAccountData {
            wrapped_account_cryptographic_state,
            folders: vec![],
            ciphers: vec![],
            sends: vec![],
            emergency_access_memberships: vec![],
            organization_memberships: vec![],
            trusted_devices: vec![],
            passkeys: vec![],
            kdf_and_salt,
        }
    }

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

    fn assert_symmetric_keys_equal(
        key_id_1: SymmetricKeySlotId,
        key_id_2: SymmetricKeySlotId,
        ctx: &mut KeyStoreContext<KeySlotIds>,
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
    fn test_from_key_rotation_method_password_returns_input() {
        let kdf = create_test_kdf_pbkdf2();
        let salt = "test@example.com".to_string();
        let synced_data = make_synced_account_data(Some((kdf.clone(), salt.clone())));

        let result = PrimaryUnlockMethod::from_key_rotation_method(
            KeyRotationMethod::Password {
                password: "pass".to_string(),
            },
            &synced_data,
            None,
        );

        let input = result.expect("should succeed");
        let PrimaryUnlockMethod::Password {
            password,
            kdf: result_kdf,
            salt: result_salt,
        } = input
        else {
            panic!("expected Password variant");
        };
        assert_eq!(password, "pass");
        assert_eq!(result_kdf, kdf);
        assert_eq!(result_salt, salt);
    }

    #[test]
    fn test_from_key_rotation_method_password_no_kdf_returns_error() {
        let synced_data = make_synced_account_data(None);

        let result = PrimaryUnlockMethod::from_key_rotation_method(
            KeyRotationMethod::Password {
                password: "pass".to_string(),
            },
            &synced_data,
            None,
        );

        assert!(matches!(result, Err(RotateUserKeysError::Api)));
    }

    #[test]
    fn test_from_key_rotation_method_key_connector_returns_input() {
        let synced_data = make_synced_account_data(None);
        let key = KeyConnectorKey::make();
        let expected_b64: bitwarden_encoding::B64 = key.clone().into();

        let result = PrimaryUnlockMethod::from_key_rotation_method(
            KeyRotationMethod::KeyConnector {
                key_connector_url: "https://kc.example.com".to_string(),
            },
            &synced_data,
            Some(key),
        );

        let PrimaryUnlockMethod::KeyConnector { key_connector_key } =
            result.expect("should succeed")
        else {
            panic!("expected KeyConnector variant");
        };
        let actual_b64: bitwarden_encoding::B64 = key_connector_key.into();
        assert_eq!(actual_b64.to_string(), expected_b64.to_string());
    }

    #[test]
    fn test_from_key_rotation_method_key_connector_no_key_returns_error() {
        let synced_data = make_synced_account_data(None);

        let result = PrimaryUnlockMethod::from_key_rotation_method(
            KeyRotationMethod::KeyConnector {
                key_connector_url: "https://kc.example.com".to_string(),
            },
            &synced_data,
            None,
        );

        assert!(matches!(result, Err(RotateUserKeysError::KeyConnectorApi)));
    }

    #[test]
    fn test_from_key_rotation_method_tde_returns_error() {
        let synced_data = make_synced_account_data(None);

        let result = PrimaryUnlockMethod::from_key_rotation_method(
            KeyRotationMethod::Tde,
            &synced_data,
            None,
        );

        assert!(matches!(
            result,
            Err(RotateUserKeysError::UnimplementedKeyRotationMethod)
        ));
    }

    #[test]
    fn test_reencrypt_unlock_method_data_password_pbkdf2() {
        let mock_password = "test_password".to_string();
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let user_key_id = ctx.generate_symmetric_key();

        let input = PrimaryUnlockMethod::Password {
            password: mock_password.clone(),
            kdf: create_test_kdf_pbkdf2(),
            salt: "test@example.com".to_string(),
        };

        let result = reencrypt_unlock_method_data(input, user_key_id, &mut ctx);

        let model = result.expect("should be ok");
        assert_eq!(model.unlock_method, UnlockMethod::MasterPassword);
        assert!(model.master_password_unlock_data.is_some());
        assert!(model.key_connector_key_wrapped_user_key.is_none());

        let master_password_unlock_data_model = model
            .master_password_unlock_data
            .expect("should be present");
        let master_password_unlock_data = MasterPasswordUnlockData {
            master_key_wrapped_user_key: master_password_unlock_data_model
                .master_key_wrapped_user_key
                .parse()
                .expect("should parse"),
            kdf: create_test_kdf_pbkdf2(),
            salt: "test@example.com".to_string(),
        };
        let decrypted_user_key = master_password_unlock_data
            .unwrap_to_context(&mock_password, &mut ctx)
            .expect("unwrap should succeed");
        assert_symmetric_keys_equal(user_key_id, decrypted_user_key, &mut ctx);
    }

    #[test]
    fn test_reencrypt_unlock_method_data_password_argon2id() {
        let mock_password = "test_password".to_string();
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let user_key_id = ctx.generate_symmetric_key();

        let input = PrimaryUnlockMethod::Password {
            password: mock_password.clone(),
            kdf: create_test_kdf_argon2id(),
            salt: "test@example.com".to_string(),
        };

        let result = reencrypt_unlock_method_data(input, user_key_id, &mut ctx);
        assert!(result.is_ok());

        let model = result.expect("should be ok");
        assert_eq!(model.unlock_method, UnlockMethod::MasterPassword);
        assert!(model.master_password_unlock_data.is_some());
        assert!(model.key_connector_key_wrapped_user_key.is_none());

        let master_password_unlock_data_model = model
            .master_password_unlock_data
            .expect("should be present");
        let master_password_unlock_data = MasterPasswordUnlockData {
            master_key_wrapped_user_key: master_password_unlock_data_model
                .master_key_wrapped_user_key
                .parse()
                .expect("should parse"),
            kdf: create_test_kdf_argon2id(),
            salt: "test@example.com".to_string(),
        };
        let decrypted_user_key = master_password_unlock_data
            .unwrap_to_context(&mock_password, &mut ctx)
            .expect("unwrap should succeed");
        assert_symmetric_keys_equal(user_key_id, decrypted_user_key, &mut ctx);
    }

    #[test]
    fn test_reencrypt_unlock_method_data_key_connector() {
        let key_connector_key = KeyConnectorKey::make();
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let user_key_id = ctx.generate_symmetric_key();

        let input = PrimaryUnlockMethod::KeyConnector {
            key_connector_key: key_connector_key.clone(),
        };

        let result = reencrypt_unlock_method_data(input, user_key_id, &mut ctx);

        let model = result.expect("should be ok");
        assert_eq!(model.unlock_method, UnlockMethod::KeyConnector);
        assert!(model.master_password_unlock_data.is_none());
        let wrapped_user_key_str = model
            .key_connector_key_wrapped_user_key
            .expect("should be present");
        let wrapped_user_key: bitwarden_crypto::EncString =
            wrapped_user_key_str.parse().expect("should parse");

        let unwrapped_user_key_id = key_connector_key
            .unwrap_user_key(wrapped_user_key, &mut ctx)
            .expect("unwrap should succeed");
        assert_symmetric_keys_equal(user_key_id, unwrapped_user_key_id, &mut ctx);
    }
}
